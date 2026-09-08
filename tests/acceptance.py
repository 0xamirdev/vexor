#!/usr/bin/env python3
"""VEXOR acceptance suite.

Builds the CLI binary, boots the deliberately vulnerable test server
(tests/vulnserver), runs a full scan, and asserts the reporting contract:

  1. Client-side SDK tokens (websiteToken) produce ZERO findings.
  2. robots.txt produces ZERO findings (no exposure, no header noise).
  3. Missing-security-header findings are aggregated into at most one.
  4. Unverified credential patterns are labeled "Potential" and capped at
     medium severity, with no fabricated exploitation PoC.
  5. Verified finding classes (SQLi, XSS) still work and their PoCs embed
     the actual payload.
  6. `--version` prints the tool version.

Stdlib only. Exit code 0 = contract holds, 1 = regression.
"""

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "build", "vexor")
VULNSERVER = os.path.join(ROOT, "tests", "vulnserver", "main.go")
PORT = os.environ.get("VEXOR_TEST_PORT", "8123")
BASE = f"http://127.0.0.1:{PORT}"

failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def build():
    os.makedirs(os.path.dirname(BIN), exist_ok=True)
    subprocess.run(["go", "build", "-o", BIN, "./cmd/vexor"], cwd=ROOT, check=True)


def start_server():
    proc = subprocess.Popen(
        ["go", "run", VULNSERVER],
        env={**os.environ, "PORT": PORT},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )
    for _ in range(50):
        try:
            urllib.request.urlopen(BASE + "/", timeout=1)
            return proc
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("vulnserver did not come up")


def run_scan():
    outdir = tempfile.mkdtemp(prefix="vexor-acc-")
    res = subprocess.run(
        [BIN, "-u", BASE, "-t", "8", "-timeout", "8", "-p", "20", "-o", outdir],
        cwd=ROOT, capture_output=True, text=True, timeout=420,
    )
    jsons = [f for f in os.listdir(outdir) if f.endswith(".json")]
    if not jsons:
        raise RuntimeError(f"no JSON report produced\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}")
    with open(os.path.join(outdir, jsons[0])) as fh:
        report = json.load(fh)
    return res, report


def main():
    print("== VEXOR acceptance suite ==")

    print("[1/5] building binary")
    build()

    print("[2/5] checking --version")
    ver = subprocess.run([BIN, "--version"], capture_output=True, text=True)
    check("--version exits 0", ver.returncode == 0)
    check("--version prints VEXOR <semver>", bool(re.match(r"^VEXOR \d+\.\d+\.\d+$", ver.stdout.strip())),
          repr(ver.stdout))

    # CLI contract: the binary must behave identically from ANY working
    # directory (no repo-relative resources). Run from /tmp explicitly.
    foreign = tempfile.mkdtemp(prefix="vexor-cwd-")
    ver2 = subprocess.run([BIN, "--version"], capture_output=True, text=True, cwd=foreign)
    check("--version works from a foreign cwd", ver2.returncode == 0 and ver2.stdout.strip() == ver.stdout.strip(),
          repr(ver2.stdout))

    # go install path: install into an isolated GOBIN and execute from /tmp.
    gobin = tempfile.mkdtemp(prefix="vexor-gobin-")
    inst = subprocess.run(["go", "install", "./cmd/vexor"], cwd=ROOT,
                          env={**os.environ, "GOBIN": gobin}, capture_output=True, text=True)
    check("go install ./cmd/vexor succeeds", inst.returncode == 0, inst.stderr)
    installed = os.path.join(gobin, "vexor")
    if os.path.exists(installed):
        ver3 = subprocess.run([installed, "--version"], capture_output=True, text=True, cwd="/tmp")
        check("installed binary runs from /tmp", ver3.returncode == 0 and "VEXOR" in ver3.stdout, repr(ver3.stdout))

    print("[3/5] starting vulnserver")
    server = start_server()
    try:
        print("[4/5] running scan")
        res, report = run_scan()

        findings = report.get("findings", [])
        titles = [f.get("title", "") for f in findings]
        endpoints = [f.get("endpoint", "") for f in findings]

        # 1. Client-side SDK token: zero findings.
        token_hits = [f for f in findings if "vxPubTok9q2ZxKc4MnR7sDw3" in json.dumps(f)]
        check("websiteToken produces zero findings", not token_hits,
              f"found {len(token_hits)}: {[f['title'] for f in token_hits]}")
        publishable_hits = [f for f in findings if "pk_test" in json.dumps(f)]
        check("publishableKey produces zero findings", not publishable_hits,
              f"found {len(publishable_hits)}")

        # 2. robots.txt: zero findings.
        robots_hits = [e for e in endpoints if e.endswith("/robots.txt")]
        check("robots.txt produces zero findings", not robots_hits, f"{robots_hits}")

        # 3. Header findings aggregated to <= 1.
        header_findings = [f for f in findings if "Missing Security Headers" in f.get("title", "")]
        check("security-header findings aggregated (<=1)", len(header_findings) <= 1,
              f"{len(header_findings)} separate findings")

        # 4. Unverified credentials: Potential label, medium cap, no fake PoC.
        #    (Secret-category findings carry a Payload = category name; file
        #    exposures like "Exposed .env File" are verified-by-readability
        #    and legitimately critical.)
        for f in findings:
            if f.get("module") == "exposure" and f.get("payload") and "AKIA" in json.dumps(f):
                check("AWS key labeled Potential (unverified)",
                      "Potential" in f["title"] and "unverified" in f["title"].lower(), f["title"])
                check("unverified credential severity <= medium",
                      f["severity"] in ("low", "medium", "info"), f["severity"])
                check("unverified credential has no exploit PoC",
                      "Authorization: Bearer" not in (f.get("poc_curl") or ""),
                      f.get("poc_curl", ""))
        check(".env file exposure still detected as critical",
              any("Exposed .env File" in f.get("title", "") and f["severity"] == "critical"
                  for f in findings))

        # 5. Core detection still works with payload-embedded PoCs.
        check("SQLi error-based still detected",
              any("SQL Injection" in t for t in titles), str(titles))
        check("XSS still detected", any("Reflected XSS" in t for t in titles))
        sqli_pocs = [f.get("poc_curl", "") for f in findings if "SQL Injection" in f.get("title", "")]
        check("SQLi PoC embeds the payload", any("id=" in p for p in sqli_pocs), str(sqli_pocs))
        check("CORS misconfig detected", any("CORS" in t for t in titles))
        check("chained findings produced", report.get("chained_findings", 0) >= 1)

        # Report metadata contract.
        check("JSON report carries tool_version", report.get("tool_version") == "1.1.2",
              str(report.get("tool_version")))

        print("[5/5] done")
    finally:
        os.killpg(os.getpgid(server.pid), signal.SIGTERM)

    if failures:
        print(f"\n{len(failures)} check(s) FAILED: {failures}")
        sys.exit(1)
    print("\nAll acceptance checks passed.")


if __name__ == "__main__":
    main()
