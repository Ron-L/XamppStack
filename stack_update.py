"""stack_update.py -- keep XAMPP's PHP (and the Apache report) current.

XAMPP has no update channel: Apache Friends stopped at 8.2.12 (Nov 2023). PHP
is patched by swapping C:\\xampp\\php with the official Windows build from
php.net, which is a drop-in for XAMPP's folder (php.ini is not in the zip,
so XAMPP's own php.ini with its timezone / extension list stays).

    py stack_update.py                 check: installed vs latest; exit 1 if behind
    py stack_update.py --apply         download, verify, stage, loader check,
                                       stop Apache, swap, start, smoke test
                                       (needs an ELEVATED window for the swap)
    py stack_update.py --apply --dry-run   everything except stop/swap/start
    py stack_update.py --apply --branch 8.4   move to another branch (vs17 build)
    py stack_update.py --apply --reinstall    re-run the pipeline on the installed version

Why the loader check: Apache resolves an extension's helper DLLs from its own
bin folder, not from C:\\xampp\\php, and its copies are from 2023. PHP 8.2.35's
curl extension needed four `LoadFile "C:/xampp/php/<dll>"` lines in
apache\\conf\\extra\\httpd-xampp.conf before it would load (2026-10-21). The
check loads every enabled extension from the STAGED build the way Apache
will -- apache\\bin on the search path, the LoadFile DLLs pre-loaded -- and
refuses to swap while any fails, naming the DLL it could not find.

Rollback: C:\\xampp\\php-<old version>.bak, made before the swap (robocopy /MIR
it back over C:\\xampp\\php, then start Apache2.4).
"""
import argparse
import ctypes
import hashlib
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime
import io
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.request
import zipfile

try:
    from pytools.keepopen import run
except ImportError:
    print("This script needs the pytools submodule. In the project folder run:\n"
          "    git submodule update --init\n"
          "then start it again.", file=sys.stderr)
    try:
        input("\nPress Enter to close this window.")
    except (EOFError, KeyboardInterrupt):   # no keyboard (run by another tool) -- just exit
        pass
    sys.exit(1)

XAMPP = r"C:\xampp"
PHP_DIR = os.path.join(XAMPP, "php")
APACHE_BIN = os.path.join(XAMPP, "apache", "bin")
XAMPP_CONF = os.path.join(XAMPP, "apache", "conf", "extra", "httpd-xampp.conf")
ERROR_LOG = os.path.join(XAMPP, "apache", "logs", "error.log")
UPDATES = os.path.join(XAMPP, "updates")           # downloads + staging live here
SERVICE = "Apache2.4"
# The WINDOWS feed, not the source-release feed: Windows binaries get rebuilt
# with the same PHP version when a bundled library is fixed (2026-10-26:
# 8.2.35 -> 8.2.35-1 for Brotli CVE-2026-111497). The source feed never
# changes for those, so a check keyed on it stays green while the server
# runs the bad build. This feed names the build ("8.2.35-1"), the zip and
# its SHA-256.
WIN_FEED = "https://www.php.net/backend/win-releases.json"
WIN_RELEASES = "https://windows.php.net/downloads/releases/"
WIN_ARCHIVES = "https://windows.php.net/downloads/releases/archives/"
APACHE_LOUNGE = "https://www.apachelounge.com/download/"
SMOKE_URL = "https://localhost/"
MARKER = os.path.join(PHP_DIR, "stack_update.json")   # which BUILD is installed (written at swap)
SNAPSHOT = os.path.join(PHP_DIR, "snapshot.txt")      # php.net build stamp (fallback for hand installs)

INSECURE = ssl.create_default_context()
INSECURE.check_hostname = False
INSECURE.verify_mode = ssl.CERT_NONE


# --- small helpers -----------------------------------------------------------

def say(msg):
    print(msg, flush=True)


def fetch(url, binary=False, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "stack_update.py"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return data if binary else data.decode("utf-8", "replace")


def run_out(cmd, cwd=None):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd).stdout


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def vtuple(v):
    # "8.4.27-1" -> (8, 4, 27, 1); "8.4.27" -> (8, 4, 27, 0)
    core, _, rebuild = v.partition("-")
    return tuple(int(x) for x in core.split(".")) + (int(rebuild or 0),)


def plain(build):
    # "8.2.35-1" -> "8.2.35" (what php -v and the Server header show)
    return build.partition("-")[0]


# --- what is installed / what is current -------------------------------------

def installed_php():
    out = run_out([os.path.join(PHP_DIR, "php.exe"), "-v"])
    m = re.search(r"PHP (\d+\.\d+\.\d+)", out)
    info = run_out([os.path.join(PHP_DIR, "php.exe"), "-i"])
    vs = "vs17" if "Visual C++ 2022" in info else "vs16" if "Visual C++ 2019" in info else "?"
    return (m.group(1) if m else "?"), vs


def installed_build():
    # The exact build in C:\xampp\php: the marker this script writes at swap
    # time, else (a hand install) the version plus the php.net build stamp
    # from snapshot.txt, so a rebuild can still be told from its date.
    version, vs = installed_php()
    built = None
    try:
        with open(MARKER, encoding="utf-8") as f:
            return json.load(f)["build"], vs, None
    except (OSError, KeyError, ValueError):
        pass
    try:
        with open(SNAPSHOT, encoding="utf-8", errors="replace") as f:
            m = re.search(r"generated on\s+(.+)", f.read())
        if m:
            built = parsedate_to_datetime(m.group(1).strip())
    except OSError:
        pass
    return version, vs, built


def latest_build(branch, vs):
    # The current Windows build for a branch from the Windows feed:
    # {"build": "8.2.35-1", "zip": "php-8.2.35-1-Win32-vs16-x64.zip",
    #  "sha256": ..., "mtime": datetime}. Thread-safe x64 only.
    d = json.loads(fetch(WIN_FEED))
    if branch not in d:
        raise SystemExit("branch %s is not in the Windows feed (%s)" % (branch, ", ".join(sorted(d))))
    e = d[branch]
    keys = [k for k in e if k.startswith("ts-") and k.endswith("-x64")]
    if not keys:
        raise SystemExit("no thread-safe x64 build listed for %s" % branch)
    key = "ts-%s-x64" % vs if "ts-%s-x64" % vs in keys else keys[0]
    z = e[key]["zip"]
    return {"build": e["version"], "zip": z["path"], "sha256": z["sha256"].lower(),
            "mtime": datetime.fromisoformat(e[key]["mtime"]), "vs": key.split("-")[1]}


def is_behind(installed, built, latest):
    # installed: "8.2.35" or "8.2.35-1"; built: snapshot datetime or None.
    # A later version is behind; so is the same version when the feed shows a
    # rebuild ("-1") and our build predates it (the stamp is minutes before
    # the upload, so a day of slack is safe).
    if vtuple(plain(installed)) < vtuple(plain(latest["build"])):
        return True
    if "-" in installed or "-" not in latest["build"]:
        return vtuple(installed) < vtuple(latest["build"])
    return built is not None and built < latest["mtime"] - timedelta(days=1)


def installed_apache():
    out = run_out([os.path.join(APACHE_BIN, "httpd.exe"), "-v"])
    m = re.search(r"Apache/(\d+\.\d+\.\d+)", out)
    return m.group(1) if m else "?"


def latest_apache():
    try:
        page = fetch(APACHE_LOUNGE)
        versions = set(re.findall(r"httpd-(2\.4\.\d+)", page))
        return max(versions, key=vtuple) if versions else "?"
    except Exception as e:
        return "? (%s)" % e


def check():
    v, vs, built = installed_build()
    branch = ".".join(plain(v).split(".")[:2])
    behind = False
    say("PHP installed : %s (%s, thread safe%s)"
        % (v, vs, ", built %s" % built.strftime("%d %b %Y") if built else ""))
    for b in sorted({branch, "8.4"}, key=vtuple):
        lb = latest_build(b, vs if b == branch else "vs17")
        mark = ""
        if b == branch:
            behind = is_behind(v, built, lb)
            mark = "  <- current branch, " + ("BEHIND" if behind else "UP TO DATE")
        say("PHP %s latest: %s (%s)%s" % (b, lb["build"], lb["mtime"].strftime("%d %b %Y"), mark))
    if branch == "8.2":
        say("NOTE: PHP 8.2 security support ends 2026-12-31 -- move to 8.4 before then")
    a = installed_apache()
    la = latest_apache()
    say("Apache installed: %s   Apache Lounge latest: %s%s"
        % (a, la, "   (report only; Apache is not updated by this script)"
           if la == "?" or vtuple(la) <= vtuple(a) else "   BEHIND (report only)"))
    return behind


# --- download, verify, stage -------------------------------------------------

def download(latest):
    # The zip the Windows feed names, with the SHA-256 it publishes. Current
    # builds sit in releases/; one that has just been superseded, in archives/.
    os.makedirs(UPDATES, exist_ok=True)
    name = latest["zip"]
    path = os.path.join(UPDATES, name)
    if not os.path.exists(path):
        for base in (WIN_RELEASES, WIN_ARCHIVES):
            try:
                say("downloading %s" % (base + name))
                data = fetch(base + name, binary=True, timeout=600)
                break
            except Exception as e:
                say("  not there (%s)" % e)
        else:
            raise SystemExit("could not download " + name)
        with open(path, "wb") as f:
            f.write(data)
    got = hashlib.sha256(open(path, "rb").read()).hexdigest()
    if got != latest["sha256"]:
        os.remove(path)
        raise SystemExit("SHA-256 mismatch for %s -- deleted; run again" % name)
    say("verified  %s  (SHA-256 matches php.net)" % name)
    return path


def stage(zip_path, build):
    folder = os.path.join(UPDATES, "php-%s-stage" % build)
    if os.path.isdir(folder):
        shutil.rmtree(folder)
    zipfile.ZipFile(zip_path).extractall(folder)
    for must in ("php.exe", "php8ts.dll", "php8apache2_4.dll"):
        if not os.path.isfile(os.path.join(folder, must)):
            raise SystemExit("staged build lacks " + must)
    if os.path.isfile(os.path.join(folder, "php.ini")):
        raise SystemExit("the zip carries a php.ini -- it would replace XAMPP's; stopping")
    say("staged    %s" % folder)
    return folder


# --- the loader check: will Apache be able to load every extension? ----------

def enabled_extensions():
    exts = []
    for line in io.open(os.path.join(PHP_DIR, "php.ini"), encoding="utf-8", errors="replace"):
        m = re.match(r"\s*extension\s*=\s*\"?([A-Za-z0-9_.]+)\"?", line)
        if m:
            name = m.group(1)
            if not name.endswith(".dll"):
                name = "php_%s.dll" % name
            exts.append(name)
    return exts


def loadfile_lines():
    names = []
    for line in io.open(XAMPP_CONF, encoding="utf-8", errors="replace"):
        m = re.match(r'\s*LoadFile\s+"C:/xampp/php/([^"]+)"', line)
        if m:
            names.append(m.group(1))
    return names


def dll_imports(path):
    blob = open(path, "rb").read()
    return sorted(set(m.decode() for m in re.findall(rb"[A-Za-z0-9_\-]+\.dll", blob)))


def loader_check(staged):
    say("loader check: every enabled extension, loaded the way Apache loads it")
    os.add_dll_directory(APACHE_BIN)
    for name in loadfile_lines():
        p = os.path.join(staged, name)
        if not os.path.isfile(p):
            say("  WARNING: httpd-xampp.conf pre-loads %s but the new build has no such file" % name)
            continue
        ctypes.WinDLL(p)
    ctypes.WinDLL(os.path.join(staged, "php8ts.dll"))
    failures = []
    for ext in enabled_extensions():
        p = os.path.join(staged, "ext", ext)
        if not os.path.isfile(p):
            failures.append((ext, "not in the new build"))
            continue
        try:
            ctypes.WinDLL(p)
            say("  ok       %s" % ext)
        except OSError as e:
            # Which import can't be found from Apache's point of view?
            missing = []
            for dep in dll_imports(p):
                if dep.lower().startswith(("api-ms", "ext-ms", "php8")) or dep.lower() == ext.lower():
                    continue
                try:
                    ctypes.WinDLL(dep)
                except OSError:
                    missing.append(dep)
            failures.append((ext, "%s%s" % (e, "; cannot resolve: " + ", ".join(missing) if missing else "")))
            say("  FAILED   %s -- %s" % (ext, failures[-1][1]))
    if failures:
        say("Fix: add LoadFile \"C:/xampp/php/<dll>\" lines for the DLLs named above to\n"
            "     %s (before the php_module line), then run again." % XAMPP_CONF)
    return failures


# --- the swap ----------------------------------------------------------------

def sc(*args):
    return run_out(["sc", *args])


def wait_state(word, tries=60):
    for _ in range(tries):
        if word in sc("query", SERVICE):
            return True
        time.sleep(1)
    return False


def backup(old_build):
    dest = os.path.join(XAMPP, "php-%s.bak" % old_build)
    if os.path.isdir(dest):
        say("backup    %s already exists -- kept" % dest)
        return dest
    subprocess.run(["robocopy", PHP_DIR, dest, "/MIR", "/NFL", "/NDL", "/NJH", "/NJS", "/R:1", "/W:1"],
                   capture_output=True)
    if not os.path.isfile(os.path.join(dest, "php.ini")):
        raise SystemExit("backup failed: " + dest)
    say("backup    %s" % dest)
    return dest


def copy_tree(src, dst):
    n = 0
    for root, _dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        out = dst if rel == "." else os.path.join(dst, rel)
        os.makedirs(out, exist_ok=True)
        for f in files:
            shutil.copy2(os.path.join(root, f), os.path.join(out, f))
            n += 1
    return n


def smoke(expected):
    v, _vs = installed_php()
    say("php -v    %s" % v)
    ok = v == expected
    try:
        req = urllib.request.Request(SMOKE_URL, headers={"User-Agent": "stack_update.py"})
        with urllib.request.urlopen(req, timeout=20, context=INSECURE) as r:
            hdr = r.headers.get("X-Powered-By", "")
            say("site      HTTP %s  X-Powered-By: %s" % (r.status, hdr))
            ok = ok and expected in hdr
    except Exception as e:
        say("site      FAILED: %s" % e)
        ok = False
    return ok


def startup_warnings(since_size):
    try:
        with open(ERROR_LOG, "rb") as f:
            f.seek(since_size)
            tail = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    return [line.strip()[:160] for line in tail.splitlines() if "PHP Startup" in line]


def write_marker(build, zip_name):
    with open(MARKER, "w", encoding="utf-8") as f:
        json.dump({"build": build, "zip": zip_name,
                   "installed": datetime.now().isoformat(timespec="seconds"),
                   "by": os.path.basename(__file__)}, f, indent=1)


def apply(branch, dry_run, reinstall):
    old, old_vs, built = installed_build()
    old_branch = ".".join(plain(old).split(".")[:2])
    branch = branch or old_branch
    latest = latest_build(branch, old_vs if branch == old_branch else "vs17")
    new = latest["build"]
    if branch == old_branch and not is_behind(old, built, latest) and not reinstall:
        say("PHP %s is current for branch %s -- nothing to do (use --reinstall to re-run the pipeline)"
            % (old, branch))
        return
    if branch != old_branch:
        say("branch move %s -> %s: php.ini is carried over unchanged; compare it with the new\n"
            "php.ini-production afterwards for settings that changed or went away" % (old, new))
    say("update    PHP %s%s -> %s" % (old, " (built %s)" % built.strftime("%d %b %Y") if built else "", new))
    zip_path = download(latest)
    staged = stage(zip_path, new)
    failures = loader_check(staged)
    if failures:
        raise SystemExit("%d extension(s) would not load under Apache -- not swapping" % len(failures))
    if dry_run:
        say("dry run: would back up, stop %s, copy %s over %s, start, smoke test" % (SERVICE, staged, PHP_DIR))
        return
    if not is_admin():
        raise SystemExit("the swap stops and starts the Apache service -- run this from an elevated window")

    bak = backup(old)
    log_size = os.path.getsize(ERROR_LOG) if os.path.isfile(ERROR_LOG) else 0
    say("stopping  %s" % SERVICE)
    sc("stop", SERVICE)
    if not wait_state("STOPPED"):
        raise SystemExit("Apache did not stop")
    say("copying   %d files" % copy_tree(staged, PHP_DIR))
    write_marker(new, latest["zip"])
    say("starting  %s" % SERVICE)
    sc("start", SERVICE)
    started = wait_state("RUNNING")
    time.sleep(3)
    warnings = startup_warnings(log_size)
    for w in warnings:
        say("  log: " + w)
    if started and smoke(plain(new)) and not warnings:
        say("DONE: PHP %s is live. Rollback copy: %s (delete after a week of normal running)" % (new, bak))
        return
    say("PROBLEM after the swap -- rolling back to %s" % old)
    sc("stop", SERVICE)
    wait_state("STOPPED")
    subprocess.run(["robocopy", bak, PHP_DIR, "/MIR", "/NFL", "/NDL", "/NJH", "/NJS", "/R:1", "/W:1"],
                   capture_output=True)          # /MIR also removes the new marker
    sc("start", SERVICE)
    raise SystemExit("rolled back to PHP %s; Apache %s" % (old, "running" if wait_state("RUNNING") else "NOT RUNNING"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="download, verify, check, swap (else: check only)")
    ap.add_argument("--dry-run", action="store_true", help="with --apply: everything except the swap")
    ap.add_argument("--branch", help="PHP branch to install, e.g. 8.4 (default: the installed branch)")
    ap.add_argument("--reinstall", action="store_true", help="with --apply: run even when already current")
    a = ap.parse_args()
    if a.apply:
        apply(a.branch, a.dry_run, a.reinstall)
    elif check():
        sys.exit("PHP is behind -- run:  py %s --apply   (elevated)" % os.path.basename(__file__))


if __name__ == "__main__":
    run(main, pause="always")
