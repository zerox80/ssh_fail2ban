#!/usr/bin/env python3
"""Debian/Ubuntu SSH root-login lockdown and Fail2ban setup.
Run: sudo python3 ssh_fail2ban_hardening.py --admin-user YOUR_USER
"""
import argparse
import fnmatch
import glob
import grp
import ipaddress
import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SSHD = Path('/etc/ssh/sshd_config')
JAIL = Path('/etc/fail2ban/jail.d/99-ssh-hardening.local')
APT_ENV = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}
KEY_RE = re.compile(
    r'(?:^|\s)(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)'
    r'|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)'
    r'\s+[A-Za-z0-9+/=]{16,}'
)


def run(*args, capture=False, env=None):
    return subprocess.run(args, check=True, text=True, env=env,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)


# --------------------------------------------------------------------------
# Hilfsfunktionen für die Admin-Prüfung
# --------------------------------------------------------------------------

def parse_sshd_t(text):
    """Ausgabe von 'sshd -T' als {schluessel: [werte pro Zeile]}."""
    result = {}
    for line in text.splitlines():
        parts = line.split(None, 1)
        if parts:
            result.setdefault(parts[0].lower(), []).append(
                parts[1].strip() if len(parts) > 1 else '')
    return result


def matches(patterns, values):
    """sshd-artiges Pattern-Matching (Wildcards, !Negation, user@host)."""
    hit = False
    for pat in patterns:
        negated = pat.startswith('!')
        pat = pat.lstrip('!').split('@', 1)[0]
        if any(fnmatch.fnmatchcase(v, pat) for v in values):
            if negated:
                return False
            hit = True
    return hit


def parse_sudo_output(out):
    """Liefert (hat_volle_rechte, ohne_passwort) aus 'sudo -l -U'."""
    marker = re.search(r'may run the following commands', out)
    if not marker:
        return False, False
    defaults = out[:marker.start()]
    default_nopasswd = bool(re.search(r'(?:^|[\s,])!authenticate\b', defaults))
    full = False
    last = None  # sudo wertet die zuletzt passende Regel aus
    for line in out[marker.end():].splitlines()[1:]:
        m = re.match(r'^\s*\(([^)]*)\)\s*(.*)$', line)
        if not m:
            continue
        runas = [t.strip() for t in m.group(1).split(':')[0].split(',')]
        if any(t.startswith('!') for t in runas):
            continue
        if not any(t in ('ALL', 'root') for t in runas):
            continue
        tm = re.match(r'^((?:[A-Za-z_]+:\s*)*)(.*)$', m.group(2))
        tags, cmd = tm.group(1), tm.group(2).strip()
        if cmd != 'ALL':
            continue
        full = True
        if 'NOPASSWD' in tags:
            last = True
        elif re.search(r'(?<!NO)PASSWD:', tags):
            last = False
        else:
            last = None
    nopasswd = last if last is not None else default_nopasswd
    return full, nopasswd


def check_sudo(name):
    if shutil.which('sudo') is None:
        raise RuntimeError('sudo ist nicht installiert.')
    env = {**os.environ, 'LC_ALL': 'C', 'LANG': 'C'}
    res = subprocess.run(['sudo', '-n', '-l', '-U', name],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, env=env)
    full, nopasswd = parse_sudo_output(res.stdout)
    if not full:
        raise RuntimeError(
            f'{name!r} hat keine uneingeschränkte sudo-Regel (… ALL). '
            f'Ohne vollen sudo-Zugriff wärst du nach der Sperre ohne Root. '
            f'Ausgabe: {(res.stdout or res.stderr).strip()!r}')
    if nopasswd:
        print(f'sudo für {name}: uneingeschränkt, ohne Passwort (NOPASSWD).', flush=True)
        return
    pw = subprocess.run(['passwd', '-S', name], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, env=env)
    fields = pw.stdout.split()
    if pw.returncode == 0 and len(fields) >= 2 and fields[1] in ('L', 'LK', 'NP'):
        raise RuntimeError(
            f'sudo verlangt ein Passwort, aber {name!r} hat keines '
            f'(Status {fields[1]}). Passwort setzen: sudo passwd {name}')
    print(f'sudo für {name}: uneingeschränkt, mit Passwort. '
          f'Stelle sicher, dass du das Passwort kennst.', flush=True)


def count_keys(path):
    """Zählt (nutzbare, eingeschränkte) Keys in einer authorized_keys-Datei."""
    usable = restricted = 0
    try:
        text = path.read_text(errors='replace')
    except OSError:
        return 0, 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        m = KEY_RE.search(line)
        if not m:
            continue
        opts = line[:m.start()]
        limited = (
            re.search(r'command=|no-pty|cert-authority', opts)
            or (re.search(r'\brestrict\b', opts) and not re.search(r'\bpty\b', opts))
        )
        if limited:
            restricted += 1
        else:
            usable += 1
    return usable, restricted


def check_secure_path(path, user):
    """Bildet die StrictModes-Prüfung von sshd nach (Datei bis Home-Verzeichnis)."""
    home = os.path.realpath(user.pw_dir)
    cur = os.path.realpath(path)
    while True:
        st = os.stat(cur)
        if st.st_uid not in (0, user.pw_uid):
            raise RuntimeError(
                f'StrictModes: {cur} gehört weder {user.pw_name} noch root.')
        if st.st_mode & 0o022:
            raise RuntimeError(
                f'StrictModes: {cur} ist für Gruppe/Andere schreibbar (chmod go-w).')
        parent = os.path.dirname(cur)
        if cur == home or parent == cur:
            break
        cur = parent


def group_names(user):
    names = set()
    for gid in os.getgrouplist(user.pw_name, user.pw_gid):
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            pass
    return names


def check_admin(name, sshd_bin):
    if name == 'root':
        raise RuntimeError('Root kann nicht der alternative SSH-Admin sein.')
    try:
        user = pwd.getpwnam(name)
    except KeyError:
        raise RuntimeError(f'Benutzer {name!r} existiert nicht.') from None
    if user.pw_shell.endswith(('nologin', 'false')):
        raise RuntimeError('Admin-Benutzer hat keine Login-Shell.')

    # Effektive sshd-Konfiguration für genau diesen Benutzer (inkl. Match-Blöcke).
    eff = parse_sshd_t(run(sshd_bin, '-T', '-C',
                           f'user={name},host=localhost,addr=127.0.0.1',
                           capture=True).stdout)

    def tokens(key):
        return [t for v in eff.get(key, []) for t in v.split()]

    if eff.get('pubkeyauthentication', ['yes'])[-1].lower() != 'yes':
        raise RuntimeError('PubkeyAuthentication ist deaktiviert. '
                           'Key-Login würde nicht funktionieren.')
    allow_users, deny_users = tokens('allowusers'), tokens('denyusers')
    allow_groups, deny_groups = tokens('allowgroups'), tokens('denygroups')
    groups = list(group_names(user))
    if allow_users and not matches(allow_users, [name]):
        raise RuntimeError(f'AllowUsers erlaubt {name!r} nicht.')
    if deny_users and matches(deny_users, [name]):
        raise RuntimeError(f'DenyUsers sperrt {name!r}.')
    if allow_groups and not matches(allow_groups, groups):
        raise RuntimeError(f'AllowGroups erlaubt keine Gruppe von {name!r}.')
    if deny_groups and matches(deny_groups, groups):
        raise RuntimeError(f'DenyGroups sperrt eine Gruppe von {name!r}.')
    methods = eff.get('authenticationmethods', ['any'])[-1]
    if methods.lower() != 'any':
        print(f'WARNUNG: AuthenticationMethods = {methods}. '
              f'Bitte sicherstellen, dass {name} diese Kombination erfüllt.', flush=True)

    # authorized_keys-Dateien laut sshd (AuthorizedKeysFile mit Token-Ersetzung)
    files = []
    for tok in tokens('authorizedkeysfile'):
        if tok.lower() == 'none':
            continue
        expanded = (tok.replace('%%', '\0').replace('%h', user.pw_dir)
                    .replace('%u', name).replace('%U', str(user.pw_uid))
                    .replace('\0', '%'))
        if not os.path.isabs(expanded):
            expanded = os.path.join(user.pw_dir, expanded)
        files.append(Path(expanded))
    key_command = any(v.strip().lower() != 'none'
                      for v in eff.get('authorizedkeyscommand', ['none']))

    usable_files, restricted = [], 0
    for f in files:
        if not f.is_file():
            continue
        usable, limited = count_keys(f)
        restricted += limited
        if usable:
            usable_files.append(f)
    if not usable_files and not key_command:
        hint = (f' ({restricted} Key(s) sind mit command=/restrict/no-pty eingeschränkt '
                f'und taugen nicht für einen Admin-Login)') if restricted else ''
        raise RuntimeError(
            f'Keine nutzbaren SSH-Keys für {name} in: '
            f'{", ".join(map(str, files)) or "(AuthorizedKeysFile none)"}{hint}. '
            f'Zuerst Key-Login einrichten.')
    if eff.get('strictmodes', ['yes'])[-1].lower() == 'yes':
        for f in usable_files:
            check_secure_path(f, user)
    if usable_files:
        print(f'SSH-Key-Login für {name} plausibel: {usable_files[0]}', flush=True)

    check_sudo(name)
    return user


# --------------------------------------------------------------------------
# sshd-Konfiguration
# --------------------------------------------------------------------------

def include_paths(pattern_line):
    for pattern in shlex.split(pattern_line):
        if not os.path.isabs(pattern):
            pattern = os.path.join('/etc/ssh', pattern)
        for p in sorted(glob.glob(pattern)):
            if os.path.isfile(p):
                yield p


def assert_no_match_root_override(path, state=None, seen=None, depth=0):
    """Bricht ab, wenn PermitRootLogin innerhalb eines Match-Blocks steht.

    Der Match-Zustand wird über Include-Dateien hinweg weitergereicht, weil
    OpenSSH ihn dort ebenfalls erbt. Fail closed statt Root nur scheinbar
    zu sperren.
    """
    state = state if state is not None else {'in_match': False}
    seen = seen if seen is not None else set()
    real = os.path.realpath(path)
    if real in seen or depth > 8:
        return
    seen.add(real)
    for raw in Path(path).read_text(errors='replace').splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if re.match(r'^Match\s+', line, re.IGNORECASE):
            state['in_match'] = True
            continue
        if state['in_match'] and re.match(r'^PermitRootLogin\s+', line, re.IGNORECASE):
            raise RuntimeError(
                f'PermitRootLogin in einem Match-Block erkannt ({path}). '
                f'Bitte manuell prüfen.')
        m = re.match(r'^Include\s+(.+)$', line, re.IGNORECASE)
        if m:
            for inc in include_paths(m.group(1)):
                assert_no_match_root_override(inc, state, seen, depth + 1)


def already_root_locked(config):
    """True, wenn die erste wirksame Direktive bereits 'PermitRootLogin no' ist."""
    for raw in config.splitlines():
        line = raw.split('#', 1)[0].strip()
        if line:
            return bool(re.fullmatch(r'PermitRootLogin\s+no', line, re.IGNORECASE))
    return False


def detect_ssh_service():
    for name in ('ssh', 'sshd'):
        res = subprocess.run(['systemctl', 'cat', f'{name}.service'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            return name
    raise RuntimeError('Weder ssh.service noch sshd.service gefunden.')


def service_active(unit):
    return subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode == 0


def socket_ports(service):
    """Ports aus der Socket-Aktivierung (Ubuntu 22.10+/24.04), falls aktiv."""
    unit = f'{service}.socket'
    if not service_active(unit):
        return []
    res = subprocess.run(['systemctl', 'show', unit, '-p', 'Listen'],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return sorted({m.group(1) for m in re.finditer(r':(\d+)\s+\(Stream\)', res.stdout)},
                  key=int)


# --------------------------------------------------------------------------
# Dateien schreiben / wiederherstellen
# --------------------------------------------------------------------------

def write_atomic(path, content, mode, uid=0, gid=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.hardening-tmp')
    try:
        with open(tmp, 'w') as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.chown(tmp, uid, gid)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def restore(path, backup):
    if backup is None:
        path.unlink(missing_ok=True)
        return
    tmp = path.with_name(path.name + '.hardening-restore')
    try:
        shutil.copy2(backup, tmp)
        st = backup.stat()
        os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def wait_for_jail(timeout=20):
    """Fail2ban braucht nach dem Neustart einen Moment, bis der Socket da ist."""
    deadline = time.monotonic() + timeout
    while True:
        res = subprocess.run(['fail2ban-client', 'status', 'sshd'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0:
            return res.stdout
        if time.monotonic() >= deadline:
            raise RuntimeError('Fail2ban-Jail sshd nicht aktiv: '
                               f'{(res.stderr or res.stdout).strip()}')
        time.sleep(1)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

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
    for ip in args.ignore_ip:
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            parser.error(f'Ungültige IP/CIDR: {ip}')
    sshd_bin = shutil.which('sshd') or '/usr/sbin/sshd'
    if not Path(sshd_bin).exists():
        parser.error('sshd fehlt.')

    # ---- Alle Prüfungen, bevor irgendetwas am System geändert wird ----
    run(sshd_bin, '-t')
    ssh_service = detect_ssh_service()
    check_admin(args.admin_user, sshd_bin)
    assert_no_match_root_override(SSHD)

    effective = run(sshd_bin, '-T', capture=True).stdout
    ports = {m.group(1) for m in re.finditer(r'^port\s+(\d+)\s*$', effective, re.M)}
    ports |= set(socket_ports(ssh_service))
    if not ports:
        raise RuntimeError('Konnte SSH-Port nicht ermitteln.')
    ports = sorted(ports, key=int)
    if not all(1 <= int(p) <= 65535 for p in ports):
        raise RuntimeError('Ungültiger SSH-Port.')

    original = SSHD.read_text()
    orig_stat = SSHD.stat()
    need_sshd_change = not already_root_locked(original)
    ssh_was_active = service_active(f'{ssh_service}.service')

    # ---- Ab hier: Systemänderungen ----
    print('Installiere Fail2ban, nftables und Python-systemd ...', flush=True)
    run('apt-get', 'update', env=APT_ENV)
    run('apt-get', 'install', '-y', 'fail2ban', 'python3-systemd', 'nftables', env=APT_ENV)

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup_dir = Path('/var/backups/ssh-fail2ban-hardening') / stamp
    backup_dir.mkdir(parents=True, mode=0o700)
    ssh_backup = backup_dir / 'sshd_config'
    shutil.copy2(SSHD, ssh_backup)
    jail_backup = None
    if JAIL.exists():
        jail_backup = backup_dir / '99-ssh-hardening.local'
        shutil.copy2(JAIL, jail_backup)

    # Erster globaler Wert gewinnt in sshd_config, daher vor jedes Include setzen.
    new_sshd = 'PermitRootLogin no\n' + original
    ignore_ips = ' '.join(['127.0.0.1/8', '::1', *args.ignore_ip])
    # Alles im [sshd]-Abschnitt, damit andere Jails (z.B. recidive) unberührt bleiben.
    new_jail = f'''# Managed by ssh_fail2ban_hardening.py
[sshd]
enabled = true
backend = systemd
port = {','.join(ports)}
mode = normal
ignoreip = {ignore_ips}
bantime = 1h
findtime = 10m
maxretry = 5
bantime.increment = true
bantime.maxtime = 1w
banaction = nftables
'''
    sshd_changed = False
    try:
        write_atomic(JAIL, new_jail, 0o644)
        run('fail2ban-client', '-t')
        run('systemctl', 'enable', 'fail2ban')
        run('systemctl', 'restart', 'fail2ban')
        print(wait_for_jail(), flush=True)

        if need_sshd_change:
            write_atomic(SSHD, new_sshd, stat.S_IMODE(orig_stat.st_mode),
                         orig_stat.st_uid, orig_stat.st_gid)
            sshd_changed = True
        run(sshd_bin, '-t')
        # Effektiven Root-Login-Wert prüfen (inkl. Match für typische Quell-IPs).
        for addr in ('127.0.0.1', '::1'):
            actual = run(sshd_bin, '-T', '-C',
                         f'user=root,host=localhost,addr={addr}', capture=True).stdout
            if not re.search(r'^permitrootlogin no$', actual, re.M):
                raise RuntimeError(f'Root-Login ist für {addr} nicht deaktiviert!')
        if need_sshd_change:
            if ssh_was_active:
                # reload behält bestehende Sitzungen bei.
                run('systemctl', 'reload', f'{ssh_service}.service')
                time.sleep(1)
                if not service_active(f'{ssh_service}.service'):
                    raise RuntimeError('SSH-Dienst ist nach dem Reload nicht mehr aktiv!')
            else:
                print('Hinweis: SSH-Dienst läuft nicht (Socket-Aktivierung). '
                      'Die neue Konfiguration gilt beim nächsten Start.', flush=True)
        else:
            print('PermitRootLogin no steht bereits an erster Stelle, '
                  'sshd_config bleibt unverändert.', flush=True)
    except BaseException:
        print('FEHLER: Stelle bisherige Konfigurationsdateien wieder her.', file=sys.stderr)
        if sshd_changed:
            restore(SSHD, ssh_backup)
            if ssh_was_active:
                subprocess.run(['systemctl', 'reload', f'{ssh_service}.service'], check=False)
        restore(JAIL, jail_backup)
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
        details = getattr(exc, 'stderr', None)
        if details:
            print(details.strip(), file=sys.stderr)
        sys.exit(1)
