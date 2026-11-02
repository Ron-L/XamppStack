# XamppStack

Keeps the PHP in Ron's XAMPP server current. XAMPP itself has no update channel
(Apache Friends stopped at 8.2.12, November 2023), so PHP security releases are
applied by swapping `C:\xampp\php` with the official Windows build from php.net —
a drop-in for XAMPP's folder, with XAMPP's own `php.ini` kept.

Born 2026-10-21, the day of PHP2Shell (CVE-2026-109618 / 109619), when the swap
was done by hand and cost two Apache restarts: the new curl extension needed four
`LoadFile` lines in `apache\conf\extra\httpd-xampp.conf` that nothing had checked
for beforehand. The script's loader check does that before anything is touched.

## Use

```
py stack_update.py                      check: installed vs latest; exit 1 if behind
py stack_update.py --apply              download, verify SHA-256, stage, loader check,
                                        back up, stop Apache, swap, start, smoke test
                                        -- run from an ELEVATED window
py stack_update.py --apply --dry-run    everything except the swap
py stack_update.py --apply --branch 8.4 move to another branch (php.ini carried over)
py stack_update.py --apply --reinstall  re-run the pipeline on the installed version
py stack_update.py --smoke              the post-swap smoke test alone, on the current install
```

A dry run exercises everything except the swap and the smoke test that follows it;
run `--smoke` once before a real `--apply` so that step is proven too.

A weekly Task Scheduler entry ("XAMPP stack check", Mondays 09:00, interactive)
runs the check in its own window, which stays open with the report. The task
calls python.exe by full path: Task Scheduler cannot resolve the `py` alias.

The check reads php.net's **Windows** feed (`backend/win-releases.json`), not the
source-release feed: Windows binaries get rebuilt under the same PHP version when a
bundled library is fixed (26 Oct 2026: `8.2.35` → `8.2.35-1` for Brotli
CVE-2026-111497), and only the Windows feed shows it. The installed build is
recorded in `C:\xampp\php\stack_update.json` at swap time; an install made by hand
is judged by the build stamp in `snapshot.txt`.

Downloads and staging folders live in `C:\xampp\updates`. The rollback copy is
`C:\xampp\php-<old version>.bak` (robocopy it back over `C:\xampp\php` with `/MIR`,
then start `Apache2.4`). Delete the `.bak` after a week of normal running.

Apache itself (Apache Lounge builds) is reported only, not updated.

`pytools` is a git submodule (`git submodule update --init` after cloning).
