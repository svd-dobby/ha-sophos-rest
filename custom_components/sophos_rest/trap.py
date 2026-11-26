"""SNMP trap receiver (v1 and v2c): every accepted trap becomes a Home Assistant event."""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime
import logging
from typing import Any, Callable

from .snmp import SnmpError, _dec_oid, _dec_value, _read_tlv

_LOGGER = logging.getLogger(__name__)

_SEQUENCE = 0x30
_TRAP_V1 = 0xA4
_TRAP_V2 = 0xA7

SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
SNMP_TRAP_ENTERPRISE = "1.3.6.1.6.3.1.1.4.3.0"

# Standard traps (RFC 3418); vendor traps keep their OID.
GENERIC_V1 = ("cold_start", "warm_start", "link_down", "link_up", "authentication_failure", "egp_neighbor_loss")
GENERIC_V2 = {f"1.3.6.1.6.3.1.1.5.{i + 1}": name for i, name in enumerate(GENERIC_V1)}


class TrapError(SnmpError):
    """The datagram is not an acceptable trap."""


def _varbinds(body: bytes) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    q = 0
    while q < len(body):
        _, vb, q = _read_tlv(body, q)
        _, oid_body, r = _read_tlv(vb, 0)
        vtag, vbody, _ = _read_tlv(vb, r)
        value = _dec_value(vtag, vbody)
        out.append((_dec_oid(oid_body), value if isinstance(value, (str, int, type(None))) else str(value)))
    return out


def parse_trap(data: bytes, community: str) -> dict[str, Any]:
    """Decode a v1 or v2c trap. Raises TrapError for anything else."""
    try:
        tag, msg, _ = _read_tlv(data, 0)
        if tag != _SEQUENCE:
            raise TrapError("not an SNMP message")
        _, version, pos = _read_tlv(msg, 0)
        _, comm, pos = _read_tlv(msg, pos)
        if comm.decode("utf-8", "replace") != community:
            raise TrapError("wrong community")
        pdu_tag, pdu, _ = _read_tlv(msg, pos)
        ver = int.from_bytes(version, "big")

        if pdu_tag == _TRAP_V1 and ver == 0:
            _, enterprise, p = _read_tlv(pdu, 0)
            _, agent, p = _read_tlv(pdu, p)
            _, generic, p = _read_tlv(pdu, p)
            _, specific, p = _read_tlv(pdu, p)
            _, ticks, p = _read_tlv(pdu, p)
            _, vbl, _ = _read_tlv(pdu, p)
            gen = int.from_bytes(generic, "big")
            spec = int.from_bytes(specific, "big")
            ent = _dec_oid(enterprise)
            # RFC 3584 mapping of a v1 trap to a v2 trap OID.
            trap_oid = f"1.3.6.1.6.3.1.1.5.{gen + 1}" if gen < 6 else f"{ent}.0.{spec}"
            return {
                "version": "v1",
                "trap_oid": trap_oid,
                "trap_name": GENERIC_V1[gen] if gen < 6 else None,
                "enterprise": ent,
                "agent_address": ".".join(str(b) for b in agent),
                "generic_trap": gen,
                "specific_trap": spec,
                "uptime": int.from_bytes(ticks, "big") / 100,
                "varbinds": _varbinds(vbl),
            }

        if pdu_tag == _TRAP_V2 and ver == 1:
            _, _rid, p = _read_tlv(pdu, 0)
            _, _status, p = _read_tlv(pdu, p)
            _, _index, p = _read_tlv(pdu, p)
            _, vbl, _ = _read_tlv(pdu, p)
            vbs = _varbinds(vbl)
            meta = dict(vbs[:2])
            trap_oid = str(meta.get(SNMP_TRAP_OID) or "")
            uptime = meta.get(SYS_UPTIME)
            return {
                "version": "v2c",
                "trap_oid": trap_oid,
                "trap_name": GENERIC_V2.get(trap_oid),
                "enterprise": next((v for o, v in vbs if o == SNMP_TRAP_ENTERPRISE), None),
                "uptime": uptime / 100 if isinstance(uptime, int) else None,
                "varbinds": [(o, v) for o, v in vbs if o not in (SYS_UPTIME, SNMP_TRAP_OID)],
            }
    except (IndexError, ValueError) as err:
        raise TrapError(f"malformed trap: {err}") from err
    raise TrapError(f"not a trap (PDU 0x{pdu_tag:02x}, version {ver})")


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: TrapReceiver) -> None:
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self._receiver.handle(data, addr[0])


class TrapReceiver:
    """Listens on UDP and calls `on_trap` for every accepted trap from `source`."""

    def __init__(
        self,
        source: str,
        community: str,
        port: int,
        on_trap: Callable[[dict[str, Any]], None],
    ) -> None:
        self.source = source
        self.community = community
        self.port = port
        self._on_trap = on_trap
        self._transport: asyncio.DatagramTransport | None = None
        self.received = 0
        self.rejected = 0
        self.last_error: str | None = None
        self.recent: deque[dict[str, Any]] = deque(maxlen=20)

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _Protocol(self), local_addr=("0.0.0.0", self.port)
        )

    def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def handle(self, data: bytes, sender: str) -> None:
        if sender != self.source:
            self.rejected += 1
            self.last_error = f"datagram from {sender} ignored (only {self.source} is accepted)"
            _LOGGER.debug(self.last_error)
            return
        try:
            trap = parse_trap(data, self.community)
        except SnmpError as err:
            self.rejected += 1
            self.last_error = str(err)
            _LOGGER.debug("SNMP trap from %s rejected: %s", sender, err)
            return
        self.received += 1
        # Readable texts only (no OID values).
        texts = [
            v for _, v in trap["varbinds"]
            if isinstance(v, str) and v.strip() and not v.replace(".", "").isdigit()
        ]
        trap["message"] = " | ".join(texts)
        trap["source"] = sender
        trap["received_at"] = datetime.now().astimezone().isoformat()
        trap["varbinds"] = [{"oid": o, "value": v} for o, v in trap["varbinds"]]
        self.recent.appendleft(trap)
        _LOGGER.debug("SNMP trap from %s: %s", sender, trap)
        self._on_trap(trap)
