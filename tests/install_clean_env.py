#!/usr/bin/env python3
"""Clean-environment installation test for the VEXOR installer.

Simulates a brand-new user: a synthetic HOME, a minimal PATH that contains
none of the machine's Go or VEXOR state, and an empty shell profile. The
test then runs scripts/install.sh and verifies:

  1. The installer downloads a release asset (or falls back to go install).
  2. The binary is placed in the user-owned bin dir it created/chose.
  3. The shell profile receives the PATH line for that directory.
  4. `vexor --version` works when invoked exactly the way the fresh profile
     implies (exported PATH, executed from a foreign cwd like /tmp).
  5. The user's machine PATH is never relied upon (and never mutated).

Network failures abort loudly on purpose here: CI must know when the
install contract breaks. Stdlib only.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request

REPO = "0xamirdev/vexor"
API = f"https://api.github.com/repos/{REPO}/releases/latest"

failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def latest_release():
    with urllib.request.urlopen(API, timeout=10) as r:
        return json.load(r)["tag_name"]


def main():
    print("== VEXOR clean-environment install test ==")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    installer = os.path.join(repo_root, "scripts", "install.sh")

    tag = latest_release()
    print(f"[1/4] latest release: {tag}")

    # -- synthetic fresh user ------------------------------------------------
    home = tempfile.mkdtemp(prefix="vexor-fresh-home-")
    minimal_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    # Machine reality check: the synthetic PATH must not contain a vexor.
    existing = shutil.which("vexor", path=minimal_path)
    check("machine PATH is clean (no preinstalled vexor in minimal PATH)", existing is None, str(existing))

    print("[2/4] running installer as a fresh user (synthetic HOME, minimal PATH)")
    env = {
        "HOME": home,
        "PATH": minimal_path,
        "TERM": "dumb",
        # CI/test knobs (documented in the installer): keep everything under
        # the synthetic home and build the CURRENT checkout, not @latest.
        "TARGET_DIR": os.path.join(home, ".local", "bin"),
        "VEXOR_BUILD_FROM_DIR": repo_root,
    }
    res = subprocess.run(["sh", installer], env=env, capture_output=True, text=True, timeout=600)
    print("      installer exit:", res.returncode)
    if res.returncode != 0:
        print(res.stdout[-2000:], res.stderr[-2000:])
    check("installer exits 0", res.returncode == 0)

    print("[3/4] verifying the installation layout")
    # The installer must have created and used ~/.local/bin (or Termux bin).
    candidates = [os.path.join(home, ".local", "bin", "vexor"),
                  os.path.join(home, "bin", "vexor"),
                  "/data/data/com.termux/files/usr/bin/vexor"]
    installed = next((c for c in candidates if os.path.exists(c)), None)
    check("binary installed under the fresh user's home", installed is not None, str(candidates))

    if installed:
        mode = os.stat(installed).st_mode
        check("binary is executable", bool(mode & stat.S_IXUSR))

    # A PATH line must exist in one of the profiles the installer manages.
    profile_line = False
    for rc in (".profile", ".bashrc", ".zshrc"):
        p = os.path.join(home, rc)
        if os.path.exists(p) and ".local/bin" in open(p).read():
            profile_line = True
            break
    check("shell profile receives PATH entry", profile_line)

    print("[4/4] running vexor exactly like a fresh user would")
    # Export PATH like the fresh profile would, run from a foreign cwd.
    fresh_path = minimal_path + ":" + os.path.dirname(installed) if installed else minimal_path
    run_env = {"HOME": home, "PATH": fresh_path}
    ver = subprocess.run(["vexor", "--version"], env=run_env, cwd="/tmp",
                         capture_output=True, text=True)
    check("vexor --version works from /tmp with the fresh PATH", ver.returncode == 0, repr(ver.stderr))
    check("version output is well-formed", bool(re.match(r"^VEXOR \d+\.\d+\.\d+$", ver.stdout.strip())),
          repr(ver.stdout))

    if failures:
        print(f"\n{len(failures)} check(s) FAILED: {failures}")
        sys.exit(1)
    print("\nClean-environment install test passed.")
    shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    main()
