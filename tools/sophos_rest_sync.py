"""Integratie sophos_rest uit de privé-repo svd-dobby/ha-sophos-rest op deze HA zetten (25 nov 2026).

  python3 sophos_rest_sync.py sleutel   -> maakt (indien nodig) een deploy key en toont de PUBLIEKE sleutel
  python3 sophos_rest_sync.py test      -> test de ssh-verbinding met GitHub
  python3 sophos_rest_sync.py status    -> geïnstalleerde versie en versie op GitHub (main)
  python3 sophos_rest_sync.py pull [ref] -> haalt main (of een tag/commit) op en kopieert
                                           custom_components/sophos_rest naar /config/custom_components
                                           (oude map eerst naar /config/git_repo/sophos_rest_bak)
Na een pull is een herstart van HA nodig. Er wordt nooit iets naar GitHub geschreven.
"""

import json
import os
import shutil
import subprocess
import sys

CFG = "/config"
SSH_DIR = CFG + "/.ssh"
KNOWN = SSH_DIR + "/known_hosts"
SLEUTEL = SSH_DIR + "/ha_sophos_rest_deploy"
REPO = CFG + "/git_repo/ha-sophos-rest"
REMOTE = "git@github.com:svd-dobby/ha-sophos-rest.git"
BRON = REPO + "/custom_components/sophos_rest"
DOEL = CFG + "/custom_components/sophos_rest"
BAK = CFG + "/git_repo/sophos_rest_bak"

ENV = dict(os.environ)
ENV["GIT_SSH_COMMAND"] = (
    f"ssh -i {SLEUTEL} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new "
    f"-o UserKnownHostsFile={KNOWN}"
)


def uit(ok=True, **kw):
    print(json.dumps({"ok": ok, **kw}, ensure_ascii=False))
    sys.exit(0 if ok else 1)


def run(args, cwd=None, check=True):
    r = subprocess.run(args, cwd=cwd, env=ENV, capture_output=True, text=True, timeout=180)
    if check and r.returncode != 0:
        uit(False, fout=" ".join(args[:3]), stderr=r.stderr.strip()[-600:])
    return r


def git(*args, check=True):
    return run(["git", "-c", "safe.directory=*"] + list(args), cwd=REPO, check=check)


def versie(pad):
    try:
        with open(os.path.join(pad, "manifest.json"), encoding="utf-8") as fh:
            return json.load(fh).get("version")
    except (OSError, ValueError):
        return None


def sleutel():
    os.makedirs(SSH_DIR, mode=0o700, exist_ok=True)
    if not os.path.exists(SLEUTEL):
        run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "ha-sophos-rest-deploy", "-f", SLEUTEL])
    with open(SLEUTEL + ".pub", encoding="utf-8") as fh:
        uit(publieke_sleutel=fh.read().strip(),
            uitleg="GitHub > ha-sophos-rest > Settings > Deploy keys > Add deploy key, NIET 'Allow write access'")


def test():
    r = run(["ssh", "-i", SLEUTEL, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
             "-o", "UserKnownHostsFile=" + KNOWN, "-T", "git@github.com"], check=False)
    tekst = (r.stderr + r.stdout).strip()
    uit("successfully authenticated" in tekst, antwoord=tekst[-300:])


def bijwerken():
    if not os.path.isdir(REPO + "/.git"):
        os.makedirs(os.path.dirname(REPO), exist_ok=True)
        run(["git", "clone", "-q", REMOTE, REPO])
    else:
        git("fetch", "-q", "--tags", "--prune", "origin")


def status():
    bijwerken()
    git_versie = None
    r = git("show", "origin/main:custom_components/sophos_rest/manifest.json", check=False)
    if r.returncode == 0:
        git_versie = json.loads(r.stdout).get("version")
    uit(geinstalleerd=versie(DOEL), github_main=git_versie,
        commit_main=git("rev-parse", "--short", "origin/main").stdout.strip())


def pull(ref):
    bijwerken()
    doel_ref = ref or "origin/main"
    git("checkout", "-q", "--detach", doel_ref)
    if not os.path.isfile(BRON + "/manifest.json"):
        uit(False, fout="geen custom_components/sophos_rest in " + doel_ref)
    oud = versie(DOEL)
    if os.path.isdir(DOEL):
        shutil.rmtree(BAK, ignore_errors=True)
        shutil.copytree(DOEL, BAK)
        shutil.rmtree(DOEL)
    shutil.copytree(BRON, DOEL, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    uit(van=oud, naar=versie(DOEL), commit=git("rev-parse", "--short", "HEAD").stdout.strip(),
        reservekopie=BAK if oud else None, let_op="herstart HA om de nieuwe versie te laden")


if __name__ == "__main__":
    actie = sys.argv[1] if len(sys.argv) > 1 else "status"
    arg = sys.argv[2] if len(sys.argv) > 2 else ""
    if actie == "sleutel":
        sleutel()
    elif actie == "test":
        test()
    elif actie == "status":
        status()
    elif actie == "pull":
        pull(arg)
    else:
        uit(False, fout="onbekende actie", acties=["sleutel", "test", "status", "pull"])
