"""Minimal read-only SNMP v2c client (GET and GETBULK walk) on asyncio.

No external dependencies and no relative imports, so the module can also be
loaded on its own by helper scripts. Only read requests are implemented.
"""

from __future__ import annotations

import asyncio
import itertools
import random
from typing import Any

# BER / SNMP tags
_INTEGER = 0x02
_OCTET_STRING = 0x04
_NULL = 0x05
_OID = 0x06
_SEQUENCE = 0x30
_IP_ADDRESS = 0x40
_COUNTER32 = 0x41
_GAUGE32 = 0x42
_TIMETICKS = 0x43
_OPAQUE = 0x44
_COUNTER64 = 0x46
_NO_SUCH_OBJECT = 0x80
_NO_SUCH_INSTANCE = 0x81
_END_OF_MIB_VIEW = 0x82
_GET = 0xA0
_GET_BULK = 0xA5
_RESPONSE = 0xA2

_VERSION_2C = 1

NO_VALUE = (_NO_SUCH_OBJECT, _NO_SUCH_INSTANCE)


class SnmpError(Exception):
    """SNMP request failed (timeout, protocol or error status)."""


class SnmpTimeout(SnmpError):
    """No answer from the agent."""


# --- encoding -------------------------------------------------------------


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def _enc_int(value: int) -> bytes:
    size = max(1, (value.bit_length() + 8) // 8)
    return _tlv(_INTEGER, value.to_bytes(size, "big", signed=True))


def _enc_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError(f"invalid OID {oid}")
    body = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        body.extend(reversed(chunk))
    return _tlv(_OID, bytes(body))


def _enc_message(community: str, pdu_tag: int, req_id: int, a: int, b: int, oids: list[str]) -> bytes:
    varbinds = b"".join(_tlv(_SEQUENCE, _enc_oid(o) + _tlv(_NULL, b"")) for o in oids)
    pdu = _tlv(pdu_tag, _enc_int(req_id) + _enc_int(a) + _enc_int(b) + _tlv(_SEQUENCE, varbinds))
    return _tlv(
        _SEQUENCE,
        _enc_int(_VERSION_2C) + _tlv(_OCTET_STRING, community.encode()) + pdu,
    )


# --- decoding -------------------------------------------------------------


def _read_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    tag = data[pos]
    pos += 1
    first = data[pos]
    pos += 1
    if first & 0x80:
        n = first & 0x7F
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    else:
        length = first
    end = pos + length
    if end > len(data):
        raise SnmpError("truncated SNMP message")
    return tag, data[pos:end], end


def _dec_oid(body: bytes) -> str:
    first = body[0]
    parts = [first // 40, first % 40] if first < 80 else [2, first - 80]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _dec_value(tag: int, body: bytes) -> Any:
    if tag == _INTEGER:
        return int.from_bytes(body, "big", signed=True)
    if tag in (_COUNTER32, _GAUGE32, _TIMETICKS, _COUNTER64):
        return int.from_bytes(body, "big", signed=False)
    if tag == _OCTET_STRING or tag == _OPAQUE:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return body.hex(":")
        return text if text.isprintable() or text == "" else body.hex(":")
    if tag == _IP_ADDRESS:
        return ".".join(str(b) for b in body)
    if tag == _OID:
        return _dec_oid(body)
    if tag == _NULL:
        return None
    if tag in (_NO_SUCH_OBJECT, _NO_SUCH_INSTANCE, _END_OF_MIB_VIEW):
        return _Missing(tag)
    return body.hex()


class _Missing:
    """Marker for noSuchObject / noSuchInstance / endOfMibView."""

    __slots__ = ("tag",)

    def __init__(self, tag: int) -> None:
        self.tag = tag

    def __repr__(self) -> str:
        return {0x80: "noSuchObject", 0x81: "noSuchInstance", 0x82: "endOfMibView"}[self.tag]


def _dec_response(data: bytes, req_id: int) -> list[tuple[str, Any]]:
    tag, msg, _ = _read_tlv(data, 0)
    if tag != _SEQUENCE:
        raise SnmpError("not an SNMP message")
    _, _version, pos = _read_tlv(msg, 0)
    _, _community, pos = _read_tlv(msg, pos)
    pdu_tag, pdu, _ = _read_tlv(msg, pos)
    if pdu_tag != _RESPONSE:
        raise SnmpError(f"unexpected PDU 0x{pdu_tag:02x}")
    _, rid, p = _read_tlv(pdu, 0)
    if int.from_bytes(rid, "big", signed=True) != req_id:
        raise SnmpError("request id mismatch")
    _, err_status, p = _read_tlv(pdu, p)
    _, err_index, p = _read_tlv(pdu, p)
    status = int.from_bytes(err_status, "big")
    if status:
        raise SnmpError(f"error status {status} at index {int.from_bytes(err_index, 'big')}")
    _, vbl, _ = _read_tlv(pdu, p)
    result: list[tuple[str, Any]] = []
    q = 0
    while q < len(vbl):
        _, vb, q = _read_tlv(vbl, q)
        _, oid_body, r = _read_tlv(vb, 0)
        vtag, vbody, _ = _read_tlv(vb, r)
        result.append((_dec_oid(oid_body), _dec_value(vtag, vbody)))
    return result


# --- transport ------------------------------------------------------------


class _Exchange(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.future: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr: Any) -> None:
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.future.done():
            self.future.set_exception(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.future.done():
            self.future.set_exception(exc or SnmpError("connection lost"))


class SnmpClient:
    """Read-only SNMP v2c client for one agent."""

    def __init__(
        self,
        host: str,
        community: str,
        port: int = 161,
        timeout: float = 2.0,
        retries: int = 2,
    ) -> None:
        self._host = host
        self._port = port
        self._community = community
        self._timeout = timeout
        self._retries = retries
        self._ids = itertools.count(random.randint(1, 1 << 20))
        self._lock = asyncio.Semaphore(4)

    async def _exchange(self, pdu_tag: int, a: int, b: int, oids: list[str]) -> list[tuple[str, Any]]:
        loop = asyncio.get_running_loop()
        last: Exception | None = None
        async with self._lock:
            for _ in range(self._retries + 1):
                req_id = next(self._ids) & 0x7FFFFFFF
                packet = _enc_message(self._community, pdu_tag, req_id, a, b, oids)
                transport, proto = await loop.create_datagram_endpoint(
                    _Exchange, remote_addr=(self._host, self._port)
                )
                try:
                    transport.sendto(packet)
                    data = await asyncio.wait_for(proto.future, self._timeout)
                    return _dec_response(data, req_id)
                except TimeoutError as err:
                    last = SnmpTimeout(f"no answer from {self._host}:{self._port}")
                    last.__cause__ = err
                except OSError as err:
                    last = SnmpError(str(err))
                finally:
                    transport.close()
        raise last or SnmpError("request failed")

    async def get(self, oids: list[str]) -> dict[str, Any]:
        """GET a list of scalar OIDs; missing objects are returned as None."""
        result: dict[str, Any] = {}
        for i in range(0, len(oids), 20):
            for oid, value in await self._exchange(_GET, 0, 0, oids[i : i + 20]):
                result[oid] = None if isinstance(value, _Missing) else value
        return result

    async def walk(self, base: str, max_repetitions: int = 25, limit: int = 5000) -> dict[str, Any]:
        """Walk a subtree with GETBULK; returns {full OID: value}."""
        base = base.strip(".")
        prefix = base + "."
        result: dict[str, Any] = {}
        current = base
        while len(result) < limit:
            rows = await self._exchange(_GET_BULK, 0, max_repetitions, [current])
            if not rows:
                break
            done = False
            for oid, value in rows:
                if isinstance(value, _Missing) or not oid.startswith(prefix):
                    done = True
                    break
                result[oid] = value
                current = oid
            if done:
                break
        return result


def table(rows: dict[str, Any], base: str) -> dict[str, dict[int, Any]]:
    """Group walked rows {base.column.index: value} into {index: {column: value}}."""
    prefix = base.strip(".") + "."
    out: dict[str, dict[int, Any]] = {}
    for oid, value in rows.items():
        if not oid.startswith(prefix):
            continue
        column, _, index = oid[len(prefix) :].partition(".")
        if not index:
            continue
        out.setdefault(index, {})[int(column)] = value
    return out
