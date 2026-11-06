"""Isolated two-container Linux TUN data-plane test."""
import asyncio
import ipaddress
import json
import select
import shutil
import os
import signal
import shlex
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
ROLE = sys.argv[1]
ROOT = Path('/tmp/helios-dataplane')
ROOT.mkdir(exist_ok=True)
RESOLVED = os.environ.get('HELIOS_TEST_RESOLVED') == '1'
TOKEN = '07' * 32
assert Path('/.dockerenv').exists()
assert socket.gethostname() == ('helios-tun-peer' if ROLE == 'peer' else 'helios-tun-client')

def ip(*args):
    return subprocess.check_output(['ip', *args], stderr=subprocess.STDOUT)

def snapshot():
    return [ip(fam, what, 'show', *(('table', 'all') if what == 'route' else ())) for fam in ['-4', '-6'] for what in ['route', 'rule']]

def listening(address):
    try:
        s = socket.create_connection(address, 0.2)
        s.close()
        return True
    except OSError:
        return False

def wait(check, label, seconds=15):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return
        time.sleep(0.05)
    raise AssertionError('timeout: ' + label)

def query(name, kind):
    labels = b''.join((bytes([len(x)]) + x.encode() for x in name.split('.'))) + b'\x00'
    return struct.pack('!6H', 0x484c, 0x0100, 1, 0, 0, 0) + labels + struct.pack('!2H', kind, 1)

def answer(data):
    end = 12
    while data[end]:
        end += data[end] + 1
    end += 1
    typ = struct.unpack_from('!H', data, end)[0]
    raw = socket.inet_pton(socket.AF_INET if typ == 1 else socket.AF_INET6, '198.51.100.20' if typ == 1 else '2001:db8:1::20') if typ in (1, 28) else b''
    return struct.pack('!6H', struct.unpack_from('!H', data)[0], 0x8180, 1, bool(raw), 0, 0) + data[12:end + 4] + (b'\xc0\x0c' + struct.pack('!2HIH', typ, 1, 30, len(raw)) + raw if raw else b'')

async def peer():
    wait(lambda: subprocess.run(['ip', 'link', 'show', 'wire'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0, 'wire', 45)
    for a in [('link', 'set', 'lo', 'up'), ('link', 'set', 'wire', 'up'), ('addr', 'add', '192.0.2.254/24', 'dev', 'wire'), ('-6', 'addr', 'add', '2001:db8::fe/64', 'dev', 'wire', 'nodad')]:
        ip(*a)
    for a in [('198.51.100.10/32', 'lo'), ('198.51.100.20/32', 'lo'), ('2001:db8:1::20/128', 'lo'), ('198.51.100.21/32', 'lo'), ('2001:db8:1::21/128', 'lo')]:
        ip('-6' if ':' in a[0] else 'addr', *(['addr', 'add'] if ':' in a[0] else ['add']), a[0], 'dev', a[1], *(('nodad',) if ':' in a[0] else ()))
    Path('/etc/resolv.conf').write_text('''nameserver 127.0.0.1
''')
    (ROOT / 'token').write_text(TOKEN)
    (ROOT / 'token').chmod(0o600)
    (ROOT / 'key').write_bytes(Path('/key.pem').read_bytes())
    (ROOT / 'key').chmod(0o600)
    (ROOT / 'server.toml').write_text(f'''schema_version=1
listen="0.0.0.0:24443"
listen_ipv6="[::]:24443"
[tls]
certificate="/cert.pem"
private_key="{ROOT}/key"
[auth]
id="test"
token_file="{ROOT}/token"
''')

    async def echo(r, w):
        try:
            while (d := (await r.read(4096))):
                w.write(w.get_extra_info('peername')[0].encode() + b'|' + d)
                await w.drain()
        finally:
            w.close()

    class UDP(asyncio.DatagramProtocol):

        def __init__(self, dns=False):
            self.dns = dns

        def connection_made(self, t):
            self.t = t

        def datagram_received(self, d, a):
            self.t.sendto(answer(d) if self.dns else a[0].encode() + b'|' + d, a)
    servers = []
    loop = asyncio.get_running_loop()
    for host, fam, kind, port in [('0.0.0.0', socket.AF_INET, socket.SOCK_STREAM, 18080), ('::', socket.AF_INET6, socket.SOCK_STREAM, 18080), ('0.0.0.0', socket.AF_INET, socket.SOCK_DGRAM, 18081), ('::', socket.AF_INET6, socket.SOCK_DGRAM, 18081)]:
        s = socket.socket(fam, kind)
        if fam == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        if kind == socket.SOCK_STREAM:
            s.listen()
            servers.append(await asyncio.start_server(echo, sock=s))
        else:
            await loop.create_datagram_endpoint(UDP, sock=s)
    await loop.create_datagram_endpoint(lambda: UDP(True), local_addr=('0.0.0.0', 53))
    with (ROOT / 'server.log').open('w') as log:
        p = subprocess.Popen(['/server', str(ROOT / 'server.toml')], stdout=log, stderr=log)
        try:
            await asyncio.sleep(0.3)
            assert p.poll() is None, (ROOT / 'server.log').read_text()
            print('peer ready', flush=True)
            await asyncio.Future()
        finally:
            p.terminate()
            p.wait(timeout=5)

def daemon():
    p = Path('/tmp/token')
    p.write_text(TOKEN)
    p.chmod(0o600)
    c = Path('/tmp/daemon.toml')
    c.write_text('''schema_version=1
listen="127.0.0.1:1080"
http_listen="127.0.0.1:18088"
control_listen="127.0.0.1:18089"
[dns]
listen="127.0.0.1:1053"
[outbound]
source_bypass=["192.0.2.1","2001:db8::1"]
dns_servers=["192.0.2.254:53"]
[node]
server="198.51.100.10:24443"
server_name="localhost"
ca_certificate="/cert.pem"
credential_id="test"
token_file="/tmp/token"
preferred_transport="quic"
[[rules]]
type="domain-suffix"
value="direct.test"
action="direct"
[[rules]]
type="domain-suffix"
value="reject.test"
action="reject"
[[rules]]
type="ip-cidr"
value="198.51.100.21/32"
action="direct"
[[rules]]
type="ip-cidr6"
value="2001:db8:1::21/128"
action="direct"
[[rules]]
type="final"
action="proxy"
''')
    os.execv('/daemon', ['/daemon', str(c)])

def dns(name, typ, fake=True):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(4)
        s.sendto(query(name, typ), ('127.0.0.53' if RESOLVED else '198.18.0.0', 53))
        d, _ = s.recvfrom(4096)
    n = 4 if typ == 1 else 16
    addr = ipaddress.ip_address(d[-n:])
    if fake:
        assert addr in ipaddress.ip_network('198.18.0.0/15' if typ == 1 else 'fdfe:dcba:9876::/96')
    else:
        assert str(addr) == ('198.51.100.20' if typ == 1 else '2001:db8:1::20'), addr
    return str(addr)

def exchange(addr, udp, direct):
    fam = socket.AF_INET6 if ':' in addr else socket.AF_INET
    data = b'x'
    with socket.socket(fam, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
        s.settimeout(4)
        s.connect((addr, 18081 if udp else 18080))
        s.sendall(data)
        r = s.recv(1024)
    source, body = r.split(b'|', 1)
    assert body == data and (source.decode() in ('2001:db8::1', '192.0.2.1')) == direct, (r, direct)

def bus(method, *arguments):
    return subprocess.check_output(['/usr/bin/busctl', '--system', '--no-pager', '--timeout=3', 'call',
        'org.freedesktop.resolve1', '/org/freedesktop/resolve1', 'org.freedesktop.resolve1.Manager',
        method, *arguments], stderr=subprocess.STDOUT)

def resolved_ready():
    try:
        bus('FlushCaches')
        return True
    except subprocess.CalledProcessError:
        return False

def start_resolved():
    # A private system bus and real resolved in this container; no host D-Bus socket is mounted.
    # Only these precreated task-temporary files become root-owned; their directories stay
    # owned by the invoking user so ordinary cleanup needs no privileged host operation.
    for name in ['passwd', 'group', 'machine-id', 'nsswitch.conf', 'systemd/resolved.conf', 'pam.d/polkit-1']:
        os.chown('/etc/' + name, 0, 0)
    Path('/etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\nsystemd-resolve:x:101:103:resolver:/run/systemd:/bin/false\nnobody:x:65534:65534:nobody:/:/bin/false\npolkitd:x:102:104:polkit:/var/lib/polkit-1:/bin/false\n')
    Path('/etc/group').write_text('root:x:0:\nsystemd-resolve:x:103:\nnogroup:x:65534:\npolkitd:x:104:\n')
    Path('/etc/machine-id').write_text('1234567890abcdef1234567890abcdef\n')
    Path('/etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files dns\n')
    Path('/etc/pam.d/polkit-1').write_text('auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_permit.so\n')
    Path('/etc/systemd').mkdir(exist_ok=True)
    Path('/etc/systemd/resolved.conf').write_text('[Resolve]\nDNS=192.0.2.254\nFallbackDNS=\nLLMNR=no\nMulticastDNS=no\nDNSSEC=no\nDNSOverTLS=no\n')
    Path('/run/dbus').mkdir(exist_ok=True)
    directory = Path('/run/systemd/resolve')
    directory.mkdir(parents=True, exist_ok=True)
    os.chown(directory, 101, 103)
    # Docker's per-container DNS bind occupies the target; supply the real stub content in-place.
    Path('/etc/resolv.conf').write_text('# systemd-resolved test stub\nnameserver 127.0.0.53\n')
    conf = ROOT / 'bus.conf'
    conf.write_text('<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
    processes = []
    for command, credentials, label in [(['/usr/bin/dbus-daemon', '--nofork', '--config-file=' + str(conf)], {}, 'bus'),
        (['/usr/bin/setpriv', '--reuid', '101', '--regid', '103', '--clear-groups',
            '--inh-caps=+net_bind_service,+net_raw,+setpcap', '--ambient-caps=+net_bind_service,+net_raw,+setpcap',
            '/usr/lib/systemd/systemd-resolved'], {}, 'resolved')]:
        with (ROOT / (label + '.log')).open('w') as log:
            processes.append(subprocess.Popen(command, stdout=log, stderr=log, **credentials))
        if label == 'bus':
            wait(lambda: Path('/run/dbus/system_bus_socket').exists(), 'private system bus')
    try:
        wait(resolved_ready, 'systemd-resolved')
    except Exception:
        print((ROOT / 'bus.log').read_text(), (ROOT / 'resolved.log').read_text(), file=sys.stderr)
        raise
    return processes

def link_dns_settings(name):
    path = shlex.split(bus('GetLink', 'i', str(socket.if_nametoindex(name))).decode())[1]
    return [subprocess.check_output(['/usr/bin/busctl', '--system', '--timeout=3', 'get-property',
        'org.freedesktop.resolve1', path, 'org.freedesktop.resolve1.Link', prop])
        for prop in ['DNSEx', 'Domains', 'DefaultRoute', 'DNSSEC', 'DNSOverTLS', 'LLMNR', 'MulticastDNS']]

def tun_dns_ready():
    if not RESOLVED:
        return Path('/etc/resolv.conf').read_text() == 'nameserver 198.18.0.0\n'
    try:
        index = socket.if_nametoindex('heliostun0')
        path = shlex.split(bus('GetLink', 'i', str(index)).decode())[1]
        domains = subprocess.check_output(['/usr/bin/busctl', '--system', '--timeout=3', 'get-property',
            'org.freedesktop.resolve1', path, 'org.freedesktop.resolve1.Link', 'Domains'], stderr=subprocess.DEVNULL)
        return b'"." true' in domains
    except (OSError, subprocess.CalledProcessError):
        return False

def client():
    for a in [('link', 'set', 'lo', 'up'), ('link', 'add', 'uplink', 'type', 'veth', 'peer', 'name', 'wire'), ('link', 'set', 'wire', 'netns', '1'), ('link', 'set', 'uplink', 'up'), ('addr', 'add', '192.0.2.1/24', 'dev', 'uplink'), ('-6', 'addr', 'add', '2001:db8::1/64', 'dev', 'uplink', 'nodad'), ('route', 'add', 'default', 'via', '192.0.2.254'), ('-6', 'route', 'add', 'default', 'via', '2001:db8::fe')]:
        ip(*a)
    ip('link', 'set', 'uplink', 'addrgenmode', 'none')
    ip('-6', 'addr', 'flush', 'dev', 'uplink', 'scope', 'link')
    Path('/etc/resolv.conf').write_text('''nameserver 192.0.2.254
''')
    wait(lambda: listening(('198.51.100.10', 24443)), 'server')
    config = ROOT / 'helper.toml'
    status = ROOT / 'status'
    stop = ROOT / 'stop'
    config.write_text(f'''schema_version=1
socks_listen="127.0.0.1:1080"
server_ip="198.51.100.10"
source_bypass=["192.0.2.1","2001:db8::1"]
tun_name="heliostun0"
ipv6_enabled=true
status_file="{status}"
stop_file="{stop}"
''')
    resolver_processes = start_resolved() if RESOLVED else []
    if RESOLVED:
        subprocess.run(['/tproxy-test', '--exact', 'linux::resolved::tests::isolated_resolved_lease_preserves_conflicts_and_recovers_unacknowledged_calls', '--ignored', '--nocapture'], check=True, timeout=30)
    baseline = snapshot()
    resolver = Path('/etc/resolv.conf').read_bytes()
    lease = Path('/var/lib/helios/tun-route-lease.json')
    with (ROOT / 'daemon.log').open('w') as log:
        d = subprocess.Popen(['/usr/bin/python3', '/test.py', 'daemon'], user=65534, group=65534, extra_groups=[], stdout=log, stderr=log)
        h = None
        try:
            wait(lambda: listening(('127.0.0.1', 1080)), 'daemon')
            info = Path(f'/proc/{d.pid}/status').read_text()
            assert 'Uid:\t65534\t65534\t65534\t65534' in info and 'CapEff:\t0000000000000000' in info
            if RESOLVED:
                # Refuse a more-specific physical domain before any network journal is created.
                uplink = str(socket.if_nametoindex('uplink'))
                bus('SetLinkDomains', 'ia(sb)', uplink, '1', 'corp.test', 'true')
                rejected_start = subprocess.run(['/helper', str(config)], capture_output=True, timeout=5)
                assert rejected_start.returncode != 0 and b'competing search/routing domains' in rejected_start.stderr, rejected_start.stderr
                assert snapshot() == baseline and not lease.exists() and not status.exists()
                bus('RevertLink', 'i', uplink)
                bus('SetLinkDNS', 'ia(iay)', uplink, '1', '2', '4', '192', '0', '2', '254')
                physical_dns = link_dns_settings('uplink')
            else:
                # Unsupported managers must be refused before status, journal or routing changes.
                Path('/etc/resolv.conf').write_text('# Generated by NetworkManager\nnameserver 192.0.2.254\n')
                rejected_start = subprocess.run(['/helper', str(config)], capture_output=True, timeout=5)
                assert rejected_start.returncode != 0 and b'managed by another service' in rejected_start.stderr
                assert snapshot() == baseline and not lease.exists() and not status.exists()
                Path('/etc/resolv.conf').write_bytes(resolver)
            for shutdown in (('stop', 'term', 'kill', 'resolver-down') if RESOLVED else ('stop', 'term', 'kill')):
                with (ROOT / 'helper.log').open('w') as hl:
                    h = subprocess.Popen(['/helper', str(config)], stdout=hl, stderr=hl)
                    wait(tun_dns_ready, 'setup')
                    # Native TCP DNS and TUN UDP DNS must hit the same daemon cache.
                    request = query('x.direct.test', 1)
                    with socket.create_connection(('198.18.0.0', 53), 4) as tcp_dns:
                        tcp_dns.settimeout(4)
                        tcp_dns.sendall(struct.pack('!H', len(request)) + request)
                        size = bytearray()
                        while len(size) < 2:
                            piece = tcp_dns.recv(2 - len(size))
                            assert piece, 'TCP DNS ended before frame length'
                            size.extend(piece)
                        length = struct.unpack('!H', size)[0]
                        reply = bytearray()
                        while len(reply) < length:
                            piece = tcp_dns.recv(length - len(reply))
                            assert piece, 'TCP DNS ended mid-frame'
                            reply.extend(piece)
                    assert str(ipaddress.ip_address(bytes(reply[-4:]))) == dns('x.direct.test', 1)
                    for name, direct in [('x.direct.test', True), ('x.proxy.test', False)]:
                        for typ in (1, 28):
                            addr = dns(name, typ)
                            for udp in (False, True):
                                exchange(addr, udp, direct)
                    for address, direct in [('198.51.100.20', False), ('2001:db8:1::20', False), ('198.51.100.21', True), ('2001:db8:1::21', True)]:
                        for udp in (False, True):
                            exchange(address, udp, direct)
                    rejected = dns('x.reject.test', 1)
                    try:
                        with socket.create_connection((rejected, 18080), 1) as stream:
                            stream.settimeout(1)
                            stream.sendall(b'blocked')
                            assert not stream.recv(1), 'Reject rule allowed data'
                    except OSError:
                        pass
                    if shutdown in ('kill', 'resolver-down'):
                        h.kill()
                        h.wait()
                        assert lease.exists()
                        os.utime(status, (0, 0))
                        if shutdown == 'resolver-down':
                            resolved = resolver_processes[-1]
                            resolved.terminate()
                            resolved.wait(timeout=5)
                            failed = subprocess.run(['/helper', '--recover', str(config)], capture_output=True, timeout=10)
                            assert failed.returncode != 0 and lease.exists() and status.exists(), failed.stderr
                            assert b'20223:' not in ip('rule', 'show')
                            with (ROOT / 'resolved.log').open('a') as output:
                                resolver_processes[-1] = subprocess.Popen(resolved.args, stdout=output, stderr=output)
                            wait(resolved_ready, 'resolved restart')
                        subprocess.run(['/helper', '--recover', str(config)], check=True, timeout=10)
                    else:
                        if shutdown == 'term':
                            h.send_signal(signal.SIGTERM)
                        else:
                            stop.write_text('stop')
                        assert h.wait(timeout=10) == 0, (ROOT / 'helper.log').read_text()
                    h = None
                if RESOLVED:
                    assert link_dns_settings('uplink') == physical_dns
                    assert b'"." true' not in subprocess.check_output(['/usr/bin/busctl', '--system', '--timeout=3', 'get-property', 'org.freedesktop.resolve1', '/org/freedesktop/resolve1', 'org.freedesktop.resolve1.Manager', 'Domains'])
                    # The same previously cached name must resolve to real IPs after recovery.
                    for typ in (1, 28):
                        dns('x.direct.test', typ, fake=False)
                current = snapshot()
                assert current == baseline, (baseline, current)
                assert Path('/etc/resolv.conf').read_bytes() == resolver and (not lease.exists()) and (not status.exists()) and (not stop.exists())
            # The production desktop interface uses only stdin JSON, fixed root paths and
            # real readiness. Copy into a trusted directory, as an installed helper would be.
            executable = '/run/helios-test-helper'
            shutil.copyfile('/helper', executable)
            os.chmod(executable, 0o755)
            desktop_status = Path('/run/helios/tun.status')
            request = dict(socks_listen='127.0.0.1:1080', server_ip='198.51.100.10',
                node_ips=['198.51.100.10'], mtu=1280, ipv6_enabled=True,
                outbound=dict(source_bypass=['192.0.2.1', '2001:db8::1'], dns_servers=['192.0.2.254:53']),
                desktop_pid=d.pid, daemon_pid=d.pid)
            def desktop_start(value):
                log = (ROOT / 'helper.log').open('w')
                process = subprocess.Popen([executable, '--desktop'], env={**os.environ, 'PKEXEC_UID': '65534'},
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, umask=0o077)
                log.close()
                process.stdin.write(json.dumps(value).encode() + b'\n')
                process.stdin.flush()
                return process
            unsafe = desktop_start({**request, 'status_file': '/etc/passwd'})
            assert unsafe.wait(timeout=10) != 0 and not lease.exists() and not desktop_status.exists()
            unsafe.stdin.close()
            mismatch = {**request, 'outbound': {**request['outbound'], 'dns_servers': ['192.0.2.253:53']}}
            h = desktop_start(mismatch)
            assert h.wait(timeout=10) != 0 and not lease.exists() and not desktop_status.exists()
            h.stdin.close()
            h = None
            assert snapshot() == baseline
            shutdown_cases = ['pipe-eof', 'helper-kill', 'network-change'] + (['resolved-down', 'foreign-domain', 'upstream-change'] if RESOLVED else ['external-dns']) + ['daemon-kill']
            for shutdown in shutdown_cases:
                h = desktop_start(request)
                assert select.select([h.stdout], [], [], 15)[0], (ROOT / 'helper.log').read_text()
                assert h.stdout.readline() == b'ready\n', (ROOT / 'helper.log').read_text()
                assert desktop_status.read_text() == 'ready\n'
                assert os.stat('/run/helios').st_mode & 0o777 == 0o755
                dns('desktop.direct.test', 1)
                exchange(dns('desktop.proxy.test', 28), False, False)
                if shutdown == 'pipe-eof':
                    h.stdin.close()
                    assert h.wait(timeout=10) == 0, (ROOT / 'helper.log').read_text()
                elif shutdown == 'helper-kill':
                    h.kill()
                    h.wait(timeout=5)
                    h.stdin.close()
                    wait(lambda: not lease.exists() and not desktop_status.exists(), 'independent root watchdog recovery')
                elif shutdown == 'network-change':
                    ip('route', 'add', '203.0.113.0/24', 'via', '192.0.2.254')
                    assert h.wait(timeout=10) != 0, (ROOT / 'helper.log').read_text()
                    h.stdin.close()
                    ip('route', 'del', '203.0.113.0/24')
                elif shutdown == 'resolved-down':
                    resolved = resolver_processes[-1]
                    resolved.terminate()
                    resolved.wait(timeout=5)
                    assert h.wait(timeout=10) != 0
                    assert lease.exists() and b'20223:' not in ip('rule', 'show')
                    with (ROOT / 'resolved.log').open('a') as output:
                        resolver_processes[-1] = subprocess.Popen(resolved.args, stdout=output, stderr=output)
                    wait(resolved_ready, 'resolved returns for automatic watchdog recovery')
                    h.stdin.close()
                elif shutdown == 'foreign-domain':
                    bus('SetLinkDomains', 'ia(sb)', str(socket.if_nametoindex('uplink')), '1', 'corp.test', 'true')
                    assert h.wait(timeout=10) != 0
                    assert b'corp.test' in link_dns_settings('uplink')[1], 'foreign domains were erased'
                    bus('SetLinkDomains', 'ia(sb)', str(socket.if_nametoindex('uplink')), '0')
                    h.stdin.close()
                elif shutdown == 'upstream-change':
                    bus('SetLinkDNS', 'ia(iay)', str(socket.if_nametoindex('uplink')), '1', '2', '4', '192', '0', '2', '253')
                    assert h.wait(timeout=10) != 0
                    assert b'253' in link_dns_settings('uplink')[0], 'foreign upstream was erased'
                    bus('SetLinkDNS', 'ia(iay)', str(socket.if_nametoindex('uplink')), '1', '2', '4', '192', '0', '2', '254')
                    h.stdin.close()
                elif shutdown == 'external-dns':
                    Path('/etc/resolv.conf').write_text('nameserver 192.0.2.253\n')
                    assert h.wait(timeout=10) != 0
                    assert Path('/etc/resolv.conf').read_text() == 'nameserver 192.0.2.253\n', 'foreign DNS was erased'
                    assert lease.exists()
                    Path('/etc/resolv.conf').write_text('nameserver 198.18.0.0\n')
                    h.stdin.close()
                else:
                    d.kill()
                    d.wait(timeout=5)
                    assert h.wait(timeout=10) != 0, (ROOT / 'helper.log').read_text()
                    h.stdin.close()
                h = None
                wait(lambda: not lease.exists() and not desktop_status.exists(), 'desktop lease cleanup')
                assert not Path('/var/lib/helios/tun-desktop-owner.json').exists()
                assert snapshot() == baseline and Path('/etc/resolv.conf').read_bytes() == resolver
                if RESOLVED:
                    assert link_dns_settings('uplink') == physical_dns
            if RESOLVED:
                # Real pkexec and polkitd. The isolated authorization rule substitutes for a
                # human entering an administrator password, only for this container's nobody UID.
                Path('/usr/share/polkit-1/actions').mkdir(parents=True, exist_ok=True)
                shutil.copyfile('/tun.policy', '/usr/share/polkit-1/actions/com.helios.tun.policy')
                Path('/etc/polkit-1/rules.d').mkdir(parents=True, exist_ok=True)
                Path('/etc/polkit-1/rules.d/00-helios-test.rules').write_text(
                    'polkit.addRule(function(action, subject) { if (action.id == "com.helios.tun" && subject.user == "nobody") return polkit.Result.NO; });\n')
                shutil.copyfile('/helper', '/usr/libexec/helios-helper')
                os.chmod('/usr/libexec/helios-helper', 0o755)
                with (ROOT / 'polkit.log').open('w') as output:
                    polkit = subprocess.Popen(['/usr/lib/polkit-1/polkitd', '--no-debug'], stdout=output, stderr=output)
                resolver_processes.append(polkit)
                def polkit_ready():
                    return subprocess.run(['/usr/bin/busctl', '--system', '--timeout=2', 'get-property',
                        'org.freedesktop.PolicyKit1', '/org/freedesktop/PolicyKit1/Authority',
                        'org.freedesktop.PolicyKit1.Authority', 'BackendName'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
                wait(polkit_ready, 'real polkit authorization service')
                denial = subprocess.run(['/client-test', '--exact', 'desktop::tests::isolated_linux_tun_desktop_pkexec_lifecycle', '--ignored', '--nocapture'],
                    user=65534, group=65534, extra_groups=[], env={**os.environ, 'HOME': '/tmp/helios-gui', 'HELIOS_ISOLATED_DESKTOP_TUN': '1', 'HELIOS_EXPECT_TUN_DENIAL': '1'}, timeout=40)
                assert denial.returncode == 0 and snapshot() == baseline and not lease.exists(), 'authorization denial was not cleaned up'
                polkit.terminate()
                polkit.wait(timeout=5)
                Path('/etc/polkit-1/rules.d/00-helios-test.rules').write_text(
                    'polkit.addRule(function(action, subject) { if (action.id == "com.helios.tun" && subject.user == "nobody") return polkit.Result.YES; });\n')
                with (ROOT / 'polkit.log').open('a') as output:
                    resolver_processes[-1] = subprocess.Popen(['/usr/lib/polkit-1/polkitd', '--no-debug'], stdout=output, stderr=output)
                wait(polkit_ready, 'polkit authorization approval fixture')
                result = subprocess.run(['/client-test', '--exact', 'desktop::tests::isolated_linux_tun_desktop_pkexec_lifecycle', '--ignored', '--nocapture'],
                    user=65534, group=65534, extra_groups=[], env={**os.environ, 'HOME': '/tmp/helios-gui', 'HELIOS_ISOLATED_DESKTOP_TUN': '1'}, timeout=60)
                if result.returncode:
                    print('POLKIT:', (ROOT / 'polkit.log').read_text(), file=sys.stderr)
                    subprocess.run(['/usr/bin/python3', '-c', "from pathlib import Path; p=Path('/tmp/helios-gui/.helios'); print([(str(f), f.read_text()) for f in p.glob('*.log')])"], user=65534, group=65534, extra_groups=[])
                    raise AssertionError('desktop pkexec lifecycle failed')
                assert snapshot() == baseline and not lease.exists() and not desktop_status.exists()
            print(('resolved (conflicts, interrupted calls, cache flush, restart); ' if RESOLVED else 'static DNS; ') + 'PASS: real TUN; unprivileged daemon; dual-stack Direct/Proxy TCP+UDP; shared DNS; Reject; manager refusal; desktop readiness/EOF; auto SIGKILL/daemon/network recovery')
        except Exception:
            print('DAEMON:', (ROOT / 'daemon.log').read_text(), file=sys.stderr)
            if RESOLVED:
                print('RESOLVED:', (ROOT / 'resolved.log').read_text(), file=sys.stderr)
            print('HELPER:', (ROOT / 'helper.log').read_text() if (ROOT / 'helper.log').exists() else '-', file=sys.stderr)
            raise
        finally:
            if h and h.poll() is None:
                h.kill()
                h.wait()
            d.terminate()
            d.wait(timeout=5)
            for process in reversed(resolver_processes):
                process.terminate()
                process.wait(timeout=5)
if ROLE == 'peer':
    asyncio.run(peer())
elif ROLE == 'daemon':
    daemon()
else:
    client()
