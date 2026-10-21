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
RELEASES = "https://www.php.net/releases/index.php?json&version=%s"
WIN_RELEASES = "https://windows.php.net/downloads/releases/"
WIN_ARCHIVES = "https://windows.php.net/downloads/releases/archives/"
APACHE_LOUNGE = "https://www.apachelounge.com/download/"
SMOKE_URL = "https://localhost/"
VS_FOR_BRANCH = {"8.2": "vs16"}                    # 8.3 and later are vs17 builds

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
    return tuple(int(x) for x in v.split("."))


# --- what is installed / what is current -------------------------------------

def installed_php():
    out = run_out([os.path.join(PHP_DIR, "php.exe"), "-v"])
    m = re.search(r"PHP (\d+\.\d+\.\d+)", out)
    info = run_out([os.path.join(PHP_DIR, "php.exe"), "-i"])
    vs = "vs17" if "Visual C++ 2022" in info else "vs16" if "Visual C++ 2019" in info else "?"
    return (m.group(1) if m else "?"), vs


def latest_php(branch):
    d = json.loads(fetch(RELEASES % branch))
    return d["version"], d.get("date", "")


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
    v, vs = installed_php()
    branch = ".".join(v.split(".")[:2])
    behind = False
    say("PHP installed : %s (%s, thread safe)" % (v, vs))
    for b in sorted({branch, "8.4"}, key=vtuple):
        lv, date = latest_php(b)
        mark = ""
        if b == branch:
            mark = "  <- current branch, UP TO DATE" if vtuple(lv) <= vtuple(v) else "  <- current branch, BEHIND"
            behind = behind or vtuple(lv) > vtuple(v)
        say("PHP %s latest: %s (%s)%s" % (b, lv, date, mark))
    if branch == "8.2":
        say("NOTE: PHP 8.2 security support ends 2026-12-31 -- move to 8.4 before then")
    a = installed_apache()
    la = latest_apache()
    say("Apache installed: %s   Apache Lounge latest: %s%s"
        % (a, la, "   (report only; Apache is not updated by this script)"
           if la == "?" or vtuple(la) <= vtuple(a) else "   BEHIND (report only)"))
    return behind


# --- download, verify, stage -------------------------------------------------

def zip_name(version, branch):
    return "php-%s-Win32-%s-x64.zip" % (version, VS_FOR_BRANCH.get(branch, "vs17"))


def published_sha(name):
    for base in (WIN_RELEASES, WIN_ARCHIVES):
        try:
            for line in fetch(base + "sha256sum.txt").splitlines():
                if line.strip().endswith(name):
                    return line.split()[0].lower(), base
        except Exception:
            pass
    raise SystemExit("no published SHA-256 found for " + name)


def download(version, branch):
    os.makedirs(UPDATES, exist_ok=True)
    name = zip_name(version, branch)
    sha, base = published_sha(name)
    path = os.path.join(UPDATES, name)
    if not os.path.exists(path):
        say("downloading %s" % (base + name))
        with open(path, "wb") as f:
            f.write(fetch(base + name, binary=True, timeout=600))
    got = hashlib.sha256(open(path, "rb").read()).hexdigest()
    if got != sha:
        os.remove(path)
        raise SystemExit("SHA-256 mismatch for %s -- deleted; run again" % name)
    say("verified  %s  (SHA-256 matches php.net)" % name)
    return path


def stage(zip_path, version):
    folder = os.path.join(UPDATES, "php-%s-stage" % version)
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


def backup(old_version):
    dest = os.path.join(XAMPP, "php-%s.bak" % old_version)
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


def apply(branch, dry_run, reinstall):
    old, old_vs = installed_php()
    branch = branch or ".".join(old.split(".")[:2])
    new, _date = latest_php(branch)
    if vtuple(new) <= vtuple(old) and not reinstall:
        say("PHP %s is current for branch %s -- nothing to do (use --reinstall to re-run the pipeline)"
            % (old, branch))
        return
    if branch != ".".join(old.split(".")[:2]):
        say("branch move %s -> %s: php.ini is carried over unchanged; compare it with the new\n"
            "php.ini-production afterwards for settings that changed or went away" % (old, new))
    say("update    PHP %s -> %s" % (old, new))
    zip_path = download(new, branch)
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
    say("starting  %s" % SERVICE)
    sc("start", SERVICE)
    started = wait_state("RUNNING")
    time.sleep(3)
    warnings = startup_warnings(log_size)
    for w in warnings:
        say("  log: " + w)
    if started and smoke(new) and not warnings:
        say("DONE: PHP %s is live. Rollback copy: %s (delete after a week of normal running)" % (new, bak))
        return
    say("PROBLEM after the swap -- rolling back to %s" % old)
    sc("stop", SERVICE)
    wait_state("STOPPED")
    subprocess.run(["robocopy", bak, PHP_DIR, "/MIR", "/NFL", "/NDL", "/NJH", "/NJS", "/R:1", "/W:1"],
                   capture_output=True)
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
