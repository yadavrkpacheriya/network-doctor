/// Router fix scripts the phone can apply DIRECTLY over the MikroTik API (no PC needed) - the same, tested
/// commands the PC app builds in nd_tools.py. Each is a (apply, undo) pair of RouterOS script text. Keeping
/// them here (not inline in the screen) makes them easy to read and keep in step with the desktop (Rakesh,
/// 24 Nov: "many functions missing in phone app"). All are reversible.
library;

class RouterFix {
  const RouterFix(this.id, this.title, this.subtitle, this.apply, this.undo, {this.danger = false});
  final String id;
  final String title;
  final String subtitle;
  final String apply;
  final String undo;
  final bool danger;
}

/// Public DNS-over-HTTPS / DNS-over-TLS resolver IPs (same list as desktop nd_tools.DOH_IPS).
const List<String> _dohIps = [
  '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112',
  '208.67.222.222', '208.67.220.220', '94.140.14.14', '94.140.15.15', '185.228.168.9', '185.228.169.9',
];

String _nameTrafficApply() {
  final addrAdds = _dohIps
      .map((ip) => '/ip firewall address-list add list=ND-DOH address=$ip comment="ND doh-block"')
      .join('\n');
  return [
    '/system logging add topics=dns,!packet action=netdoctor comment="ND dns-log"',
    ':do {/ip firewall nat remove [find where comment~"^ND dns-force"]} on-error={}',
    '/ip firewall nat add chain=dstnat protocol=udp dst-port=53 action=redirect to-ports=53 comment="ND dns-force udp53"',
    '/ip firewall nat add chain=dstnat protocol=tcp dst-port=53 action=redirect to-ports=53 comment="ND dns-force tcp53"',
    '/ip firewall filter add chain=forward protocol=tcp dst-port=853 action=drop comment="ND dns-force dot853"',
    ':do {/ip firewall filter remove [find where comment~"^ND doh-block"]} on-error={}',
    ':do {/ip firewall address-list remove [find where list=ND-DOH]} on-error={}',
    addrAdds,
    '/ip firewall filter add chain=forward protocol=tcp dst-port=443 dst-address-list=ND-DOH action=drop comment="ND doh-block 443"',
  ].join('\n');
}

const _nameTrafficUndo = ':do {/system logging remove [find where comment="ND dns-log"]} on-error={}\n'
    ':do {/ip firewall nat remove [find where comment~"^ND dns-force"]} on-error={}\n'
    ':do {/ip firewall filter remove [find where comment~"^ND dns-force"]} on-error={}\n'
    ':do {/ip firewall filter remove [find where comment~"^ND doh-block"]} on-error={}\n'
    ':do {/ip firewall address-list remove [find where list=ND-DOH]} on-error={}';

/// DHCP-full permanent fix: reserve fixed gear out of the dynamic pool + short lease (desktop v4.45).
const _dhcpFixApply =
    ':foreach L in=[/ip dhcp-server lease find where dynamic=yes status=bound] do={'
    ':local m [/ip dhcp-server lease get \$L mac-address]; :local n [:pick \$m 1 2]; '
    ':if (\$n!="2" and \$n!="6" and \$n!="a" and \$n!="e" and \$n!="A" and \$n!="E") do={'
    ':do {/ip dhcp-server lease make-static \$L} on-error={}; '
    ':do {/ip dhcp-server lease set \$L comment="ND: reserved fixed device"} on-error={}}}; '
    ':do {/ip dhcp-server lease remove [find where dynamic=yes and status!=bound]} on-error={}; '
    '/ip dhcp-server set [find] lease-time=30m';

const _dhcpFixUndo =
    ':do {/ip dhcp-server lease remove [find where comment="ND: reserved fixed device"]} on-error={}; '
    '/ip dhcp-server set [find] lease-time=1d';

const _torrentApply = ':do {/ip firewall filter remove [find where comment~"^ND guard: torrent"]} on-error={}\n'
    '/ip firewall filter add chain=forward p2p=all-p2p action=drop comment="ND guard: torrent p2p"\n'
    '/ip firewall filter add chain=forward protocol=tcp dst-port=6881-6999 action=drop comment="ND guard: torrent ports"';
const _torrentUndo = ':do {/ip firewall filter remove [find where comment~"^ND guard: torrent"]} on-error={}';

const _rogueDhcpApply =
    ':do {/interface bridge filter remove [find where comment~"^ND guard: rogue DHCP"]} on-error={}\n'
    '/interface bridge filter add chain=forward mac-protocol=ip ip-protocol=udp src-port=67 dst-port=68 '
    'action=drop comment="ND guard: rogue DHCP"';
const _rogueDhcpUndo = ':do {/interface bridge filter remove [find where comment~"^ND guard: rogue DHCP"]} on-error={}';

/// The fixes the phone offers directly on the router. Site-blocking (needs a domain list) stays its own UI.
List<RouterFix> routerFixes() => [
      RouterFix('names', 'Fix website & app names',
          'Turn on the router DNS log, send all DNS through the router, and block secure-DNS (DoH) so Usage can name sites',
          _nameTrafficApply(), _nameTrafficUndo),
      RouterFix('dhcp', 'Fix DHCP-full permanently',
          'Reserve fixed devices (cameras/NVR/PCs/printers) out of the phone pool and shorten the lease, so the pool stops filling',
          _dhcpFixApply, _dhcpFixUndo),
      RouterFix('torrent', 'Block torrents',
          'Drop peer-to-peer / torrent traffic for every device on the Wi-Fi',
          _torrentApply, _torrentUndo),
      RouterFix('roguedhcp', 'Block rogue DHCP',
          'Only this router may hand out IP addresses - a second router plugged in by its LAN port is blocked',
          _rogueDhcpApply, _rogueDhcpUndo),
    ];
