#!/usr/bin/env python3
"""Debian/Ubuntu SSH root-login lockdown and Fail2ban setup.
Run: sudo python3 ssh_fail2ban_hardening.py --admin-user YOUR_USER
"""
import argparse
import os
import pwd
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SSHD = Path('/etc/ssh/sshd_config')
JAIL = Path('/etc/fail2ban/jail.d/99-ssh-hardening.local')


def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)


def check_admin(name):
    if name == 'root':
        raise RuntimeError('Root kann nicht der alternative SSH-Admin sein.')
    try:
        user = pwd.getpwnam(name)
    except KeyError:
        raise RuntimeError(f'Benutzer {name!r} existiert nicht.') from None
    if user.pw_shell.endswith(('nologin', 'false')):
        raise RuntimeError('Admin-Benutzer hat keine Login-Shell.')
    keyfile = Path(user.pw_dir) / '.ssh/authorized_keys'
    if not keyfile.is_file() or not any(
        line.strip() and not line.lstrip().startswith('#')
        for line in keyfile.read_text(errors='replace').splitlines()
    ):
        raise RuntimeError(f'Keine SSH-Keys in {keyfile}. Zuerst Key-Login einrichten.')
    # 'sudo -l -U' may vary by policy. Require membership in Debian's admin groups,
    # as an additional safeguard, not as a guarantee that sudo is usable.
    import grp
    groups = {g.gr_name for g in grp.getgrall() if name in g.gr_mem}
    try:
        groups.add(grp.getgrgid(user.pw_gid).gr_name)
    except KeyError:
        pass
    if not groups.intersection({'sudo', 'admin'}):
        raise RuntimeError('Benutzer ist nicht in sudo/admin. Sudo-Rechte zuerst prüfen.')
    return user


def assert_no_match_root_override(config):
    # A Match block can override a global root-login setting.
    # Fail closed rather than pretend root is disabled everywhere.
    in_match = False
    for raw in config.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if re.match(r'^Match\s+', line, re.IGNORECASE):
            in_match = True
        if in_match and re.match(r'^PermitRootLogin\s+', line, re.IGNORECASE):
            raise RuntimeError('PermitRootLogin in einem Match-Block erkannt. Bitte manuell prüfen.')


def write_atomic(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.hardening-tmp')
    try:
        tmp.write_text(content)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def restore(path, backup):
    if backup is None:
        path.unlink(missing_ok=True)
    else:
        shutil.copy2(backup, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admin-user', required=True, help='Getesteter sudo-Nutzer mit SSH-Key')
    parser.add_argument('--ignore-ip', action='append', default=[],
                        help='Optional: vertrauenswürdige IP/CIDR, mehrfach verwendbar')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Bitte mit sudo/root ausführen.')
    os_release = Path('/etc/os-release').read_text()
    if not re.search(r'^ID=(?:"?)(debian|ubuntu)(?:"?)$', os_release, re.M):
        parser.error('Nur für Debian und Ubuntu vorgesehen.')
    if not SSHD.is_file():
        parser.error('OpenSSH-Serverkonfiguration fehlt.')
    check_admin(args.admin_user)
    for ip in args.ignore_ip:
        if not re.fullmatch(r'[0-9a-fA-F:.]+(?:/[0-9]{1,3})?', ip):
            parser.error(f'Ungültige IP/CIDR: {ip}')
    if shutil.which('sshd') is None:
        sshd_bin = '/usr/sbin/sshd'
    else:
        sshd_bin = shutil.which('sshd')
    if not Path(sshd_bin).exists():
        parser.error('sshd fehlt.')
    run(sshd_bin, '-t')
    print('Installiere Fail2ban, nftables und Python-systemd ...', flush=True)
    run('apt-get', 'update')
    run('apt-get', 'install', '-y', 'fail2ban', 'python3-systemd', 'nftables')

    effective = run(sshd_bin, '-T', capture=True).stdout
    ports = sorted({m.group(1) for m in re.finditer(r'^port\s+(\d+)\s*$', effective, re.M)}, key=int)
    if not ports:
        raise RuntimeError('Konnte SSH-Port nicht ermitteln.')
    if not all(1 <= int(p) <= 65535 for p in ports):
        raise RuntimeError('Ungültiger SSH-Port.')
    original = SSHD.read_text()
    assert_no_match_root_override(original)

    # Also check include files for Match-based root overrides. Global
    # settings in included files cannot override the first global value.
    included_dir = Path('/etc/ssh/sshd_config.d')
    for path in sorted(included_dir.glob('*.conf')) if included_dir.exists() else []:
        assert_no_match_root_override(path.read_text())

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup_dir = Path('/var/backups/ssh-fail2ban-hardening') / stamp
    backup_dir.mkdir(parents=True, mode=0o700)
    os.chmod(backup_dir, 0o700)
    ssh_backup = backup_dir / 'sshd_config'
    shutil.copy2(SSHD, ssh_backup)
    jail_backup = None
    if JAIL.exists():
        jail_backup = backup_dir / '99-ssh-hardening.local'
        shutil.copy2(JAIL, jail_backup)

    # First global value wins in sshd_config, so put it before any Include.
    new_sshd = 'PermitRootLogin no\n' + original
    ignore_ips = ' '.join(['127.0.0.1/8', '::1', *args.ignore_ip])
    new_jail = f'''# Managed by ssh_fail2ban_hardening.py
[DEFAULT]
ignoreip = {ignore_ips}
bantime = 1h
findtime = 10m
maxretry = 5
bantime.increment = true
bantime.maxtime = 1w
banaction = nftables
banaction_allports = nftables[type=allports]

[sshd]
enabled = true
backend = systemd
port = {','.join(ports)}
mode = normal
'''
    try:
        write_atomic(JAIL, new_jail)
        run('fail2ban-client', '-t')
        run('systemctl', 'enable', 'fail2ban')
        run('systemctl', 'restart', 'fail2ban')
        run('fail2ban-client', 'status', 'sshd')

        write_atomic(SSHD, new_sshd)
        run(sshd_bin, '-t')
        # Check effective root-login value, including Match for typical source IPs.
        for addr in ('127.0.0.1', '::1'):
            actual = run(sshd_bin, '-T', '-C',
                         f'user=root,host=localhost,addr={addr}', capture=True).stdout
            if not re.search(r'^permitrootlogin no$', actual, re.M):
                raise RuntimeError(f'Root-Login ist für {addr} nicht deaktiviert!')
        # Service is 'ssh' on Debian/Ubuntu; reloading retains active sessions.
        run('systemctl', 'reload', 'ssh')
    except Exception:
        print('FEHLER: Stelle bisherige Konfigurationsdateien wieder her.', file=sys.stderr)
        restore(SSHD, ssh_backup)
        restore(JAIL, jail_backup)
        subprocess.run(['systemctl', 'reload', 'ssh'], check=False)
        subprocess.run(['systemctl', 'restart', 'fail2ban'], check=False)
        raise

    print('\nFERTIG: Root-SSH-Login gesperrt, Fail2ban aktiv.')
    print('SSH-Ports:', ', '.join(ports))
    print('Backup:', backup_dir)
    print('WICHTIG: Neue SSH-Sitzung als', args.admin_user, 'testen, bevor du die aktuelle schließt!')
    print('Prüfen: sudo fail2ban-client status sshd')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError, OSError) as exc:
        print(f'Abbruch: {exc}', file=sys.stderr)
        sys.exit(1)
