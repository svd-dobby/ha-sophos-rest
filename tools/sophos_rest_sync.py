"""Install the sophos_rest integration on Home Assistant from the private repo svd-dobby/ha-sophos-rest.

Usage (as shell_command.sophos_rest_sync on HA):
  python3 sophos_rest_sync.py key        -> create a deploy key if needed and print the PUBLIC key
  python3 sophos_rest_sync.py test       -> test the SSH connection to GitHub
  python3 sophos_rest_sync.py status     -> installed version and version on GitHub (main)
  python3 sophos_rest_sync.py pull [ref] -> fetch main (or a tag/commit) and copy
                                            custom_components/sophos_rest to /config/custom_components
                                            (the previous folder is kept in /config/git_repo/sophos_rest_bak).
                                            This script updates itself from tools/ as well.
A restart of Home Assistant is needed after a pull. Nothing is ever written to GitHub.
"""

import filecmp
import json
import os
import shutil
import subprocess
import sys

CFG = "/config"
SSH_DIR = CFG + "/.ssh"
KNOWN = SSH_DIR + "/known_hosts"
KEY = SSH_DIR + "/ha_sophos_rest_deploy"
REPO = CFG + "/git_repo/ha-sophos-rest"
REMOTE = "git@github.com:svd-dobby/ha-sophos-rest.git"
SOURCE = REPO + "/custom_components/sophos_rest"
TARGET = CFG + "/custom_components/sophos_rest"
BACKUP = CFG + "/git_repo/sophos_rest_bak"
SELF_SOURCE = REPO + "/tools/sophos_rest_sync.py"
SELF_TARGET = CFG + "/scripts/sophos_rest_sync.py"

ENV = dict(os.environ)
ENV["GIT_SSH_COMMAND"] = (
    f"ssh -i {KEY} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new "
    f"-o UserKnownHostsFile={KNOWN}"
)


def done(ok=True, **kw):
    print(json.dumps({"ok": ok, **kw}, ensure_ascii=False))
    sys.exit(0 if ok else 1)


def run(args, cwd=None, check=True):
    r = subprocess.run(args, cwd=cwd, env=ENV, capture_output=True, text=True, timeout=180)
    if check and r.returncode != 0:
        done(False, error=" ".join(args[:3]), stderr=r.stderr.strip()[-600:])
    return r


def git(*args, check=True):
    return run(["git", "-c", "safe.directory=*"] + list(args), cwd=REPO, check=check)


def version(path):
    try:
        with open(os.path.join(path, "manifest.json"), encoding="utf-8") as fh:
            return json.load(fh).get("version")
    except (OSError, ValueError):
        return None


def key():
    os.makedirs(SSH_DIR, mode=0o700, exist_ok=True)
    if not os.path.exists(KEY):
        run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "ha-sophos-rest-deploy", "-f", KEY])
    with open(KEY + ".pub", encoding="utf-8") as fh:
        done(public_key=fh.read().strip(),
             how="GitHub > ha-sophos-rest > Settings > Deploy keys > Add deploy key, WITHOUT 'Allow write access'")


def test():
    r = run(["ssh", "-i", KEY, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
             "-o", "UserKnownHostsFile=" + KNOWN, "-T", "git@github.com"], check=False)
    text = (r.stderr + r.stdout).strip()
    done("successfully authenticated" in text, answer=text[-300:])


def fetch():
    if not os.path.isdir(REPO + "/.git"):
        os.makedirs(os.path.dirname(REPO), exist_ok=True)
        run(["git", "clone", "-q", REMOTE, REPO])
    else:
        git("fetch", "-q", "--tags", "--prune", "origin")


def status():
    fetch()
    remote_version = None
    r = git("show", "origin/main:custom_components/sophos_rest/manifest.json", check=False)
    if r.returncode == 0:
        remote_version = json.loads(r.stdout).get("version")
    done(installed=version(TARGET), github_main=remote_version,
         commit_main=git("rev-parse", "--short", "origin/main").stdout.strip())


def pull(ref):
    fetch()
    target_ref = ref or "origin/main"
    git("checkout", "-q", "--detach", target_ref)
    if not os.path.isfile(SOURCE + "/manifest.json"):
        done(False, error="no custom_components/sophos_rest in " + target_ref)
    old = version(TARGET)
    if os.path.isdir(TARGET):
        shutil.rmtree(BACKUP, ignore_errors=True)
        shutil.copytree(TARGET, BACKUP)
        shutil.rmtree(TARGET)
    shutil.copytree(SOURCE, TARGET, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    self_updated = False
    if os.path.isfile(SELF_SOURCE) and not filecmp.cmp(SELF_SOURCE, SELF_TARGET, shallow=False):
        shutil.copy2(SELF_SOURCE, SELF_TARGET)
        self_updated = True
    done(old=old, new=version(TARGET), commit=git("rev-parse", "--short", "HEAD").stdout.strip(),
         backup=BACKUP if old else None, script_updated=self_updated,
         note="restart Home Assistant to load the new version")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    arg = sys.argv[2] if len(sys.argv) > 2 else ""
    actions = {"key": key, "sleutel": key, "test": test, "status": status}
    if action == "pull":
        pull(arg)
    elif action in actions:
        actions[action]()
    else:
        done(False, error="unknown action", actions=["key", "test", "status", "pull"])
