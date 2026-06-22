"""The engine: orchestrates tor + firewall + spoofing into start/stop/status.

Designed to be fast and crash-safe:
- A single dedicated tor process we own (PID tracked in the run dir).
- Fail-closed: if anything goes wrong mid-start, we roll everything back.
- Status is cheap to compute (no heavy work) so polling stays light.
- Optionally supervised by the self-healing watchdog.
- Works on both VMs and bare-metal Linux.
"""
from __future__ import annotations

import os
import signal
import time
from dataclasses import dataclass

from . import CONFIG_DIR, DATA_DIR, RUN_DIR, TORRC_FILE
from . import config as config_mod
from . import firewall, platform as plat, spoof, torrc, watchdog
from .config import Config
from .errors import DependencyError, TorError
from .log import get_logger
from .sysutil import require_root, run, run_ok, which
from .torctl import ControlClient, wait_bootstrap

log = get_logger()

_PIDFILE = os.path.join(RUN_DIR, "tor.pid")
_CANDIDATE_TOR_USERS = ("debian-tor", "tor", "_tor")


@dataclass
class Status:
    active: bool
    tor_running: bool
    firewall_up: bool
    bootstrap: int
    pid: int | None
    watchdog: bool = False
    exit_ip: str | None = None


def _detect_tor_user() -> str:
    import pwd
    for name in _CANDIDATE_TOR_USERS:
        try:
            pwd.getpwnam(name)
            return name
        except KeyError:
            continue
    return "debian-tor"


def _ensure_dirs(tor_user: str) -> None:
    for d in (CONFIG_DIR, DATA_DIR, RUN_DIR, os.path.join(DATA_DIR, "tor")):
        os.makedirs(d, exist_ok=True)
    tor_data = os.path.join(DATA_DIR, "tor")
    if which("chown"):
        run_ok(["chown", "-R", f"{tor_user}:{tor_user}", tor_data])
        run_ok(["chown", f"{tor_user}:{tor_user}", RUN_DIR])
    os.chmod(tor_data, 0o700)
    os.chmod(RUN_DIR, 0o755)


def _read_pid() -> int | None:
    try:
        with open(_PIDFILE) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _start_tor(cfg: Config, tor_user: str) -> int:
    if which("tor") is None:
        raise DependencyError("the 'tor' package is not installed",
                              hint="Install it via ./setup.sh or your package manager.")
    torrc.write(cfg, TORRC_FILE, tor_user=tor_user)
    proc = run(["tor", "-f", TORRC_FILE, "--RunAsDaemon", "1",
                "--PidFile", _PIDFILE], timeout=30, check=False)
    if proc.returncode != 0:
        raise TorError("tor failed to launch",
                       hint=(proc.stderr or proc.stdout or "").strip()[:300] or None)
    for _ in range(20):
        pid = _read_pid()
        if _pid_alive(pid):
            return pid  # type: ignore[return-value]
        time.sleep(0.1)
    raise TorError("tor started but no live PID was found")


def start(cfg: Config | None = None, *, on_progress=None, supervise: bool = True) -> Status:
    require_root()
    cfg = cfg or config_mod.load()
    tor_user = _detect_tor_user()
    _ensure_dirs(tor_user)
    log.debug("environment: %s", plat.describe())

    started_tor = False
    try:
        if cfg.spoof_mac:
            spoof.spoof_mac()
        if cfg.spoof_hostname:
            spoof.spoof_hostname()
        if not _pid_alive(_read_pid()):
            _start_tor(cfg, tor_user)
            started_tor = True
        ok = wait_bootstrap(timeout=60, on_progress=on_progress)
        if not ok:
            raise TorError("tor did not finish bootstrapping in time",
                           hint="Check your connection or try bridges.")
        firewall.up(cfg, tor_user)
        cfg.active = True
        config_mod.save(cfg)
        if supervise and cfg.watchdog_enabled:
            try:
                watchdog.start_daemon()
            except Exception as exc:  # noqa: BLE001
                log.warning("watchdog could not start: %s", exc)
        log.info("torchain is active")
        return status(cfg)
    except Exception:
        log.error("start failed; rolling back")
        try:
            firewall.down(cfg, quiet=True)
        finally:
            if started_tor:
                _stop_tor()
            if cfg.spoof_mac or cfg.spoof_hostname:
                spoof.restore()
        raise


def _stop_tor() -> None:
    pid = _read_pid()
    if _pid_alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)  # type: ignore[arg-type]
            for _ in range(30):
                if not _pid_alive(pid):
                    break
                time.sleep(0.1)
            if _pid_alive(pid):
                os.kill(pid, signal.SIGKILL)  # type: ignore[arg-type]
        except OSError:
            pass
    try:
        os.remove(_PIDFILE)
    except OSError:
        pass


def stop(cfg: Config | None = None) -> Status:
    require_root()
    cfg = cfg or config_mod.load()
    # Stop the watchdog first so it doesn't try to revive tor.
    try:
        watchdog.stop_daemon()
    except Exception as exc:  # noqa: BLE001
        log.debug("watchdog stop: %s", exc)
    firewall.down(cfg)
    _stop_tor()
    if cfg.spoof_mac or cfg.spoof_hostname:
        spoof.restore()
    cfg.active = False
    config_mod.save(cfg)
    log.info("torchain stopped")
    return status(cfg)


def restart(cfg: Config | None = None, *, on_progress=None) -> Status:
    stop(cfg)
    return start(cfg, on_progress=on_progress)


def newnym() -> None:
    with ControlClient() as c:
        c.newnym()
    log.info("requested a new tor identity")


def status(cfg: Config | None = None) -> Status:
    cfg = cfg or config_mod.load()
    pid = _read_pid()
    tor_running = _pid_alive(pid)
    fw = firewall.is_active()
    boot = 0
    if tor_running:
        try:
            with ControlClient(timeout=2.0) as c:
                boot = c.bootstrap_progress()
        except TorError:
            boot = 0
    return Status(
        active=tor_running and fw,
        tor_running=tor_running,
        firewall_up=fw,
        bootstrap=boot,
        pid=pid,
        watchdog=watchdog.is_running(),
    )


def panic() -> None:
    """Emergency kill switch: drop ALL traffic except loopback, stop tor."""
    require_root()
    try:
        watchdog.stop_daemon()
    except Exception:  # noqa: BLE001
        pass
    if which("iptables"):
        for pol in ("OUTPUT", "INPUT", "FORWARD"):
            run_ok(["iptables", "-P", pol, "DROP"])
        run_ok(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        run_ok(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    if which("ip6tables"):
        for pol in ("OUTPUT", "INPUT", "FORWARD"):
            run_ok(["ip6tables", "-P", pol, "DROP"])
    _stop_tor()
    log.warning("PANIC engaged: all non-loopback traffic blocked")


def panic_disarm() -> None:
    require_root()
    if which("iptables"):
        for pol in ("OUTPUT", "INPUT", "FORWARD"):
            run_ok(["iptables", "-P", pol, "ACCEPT"])
        run_ok(["iptables", "-F"])
    if which("ip6tables"):
        for pol in ("OUTPUT", "INPUT", "FORWARD"):
            run_ok(["ip6tables", "-P", pol, "ACCEPT"])
    log.info("panic disarmed")
