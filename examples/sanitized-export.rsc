# Sanitized for public sharing — original credentials, MACs, and identifiers replaced
# 2026-05-24 01:46:15 by RouterOS 7.22.3
# software id = [REDACTED]
#
# model = C53UiG+5HPaxD2HPaxD
# serial number = [REDACTED]
/interface bridge
add admin-mac=xx:xx:xx:xx:xx:xx auto-mac=no comment=defconf name=bridge
add name=bridge_guest_vlan
/interface vlan
add interface=ether1 mtu=1492 name=telekom_vlan vlan-id=7
/interface pppoe-client
add add-default-route=yes allow=pap,chap,mschap2 disabled=no interface=\
    telekom_vlan max-mru=1492 max-mtu=1492 name=telekom_pppoe-out1 user=pppoe-user@isp.example.com
/interface ethernet switch
set 0 cpu-flow-control=no
/interface list
add comment=defconf name=WAN
add comment=defconf name=LAN
/interface wifi channel
add band=2ghz-ax disabled=no name=ch_2ghz reselect-interval=15m \
    skip-dfs-channels=all
add band=5ghz-ax disabled=no name=ch_5g_fixed reselect-interval=15m \
    skip-dfs-channels=10min-cac width=20/40/80mhz
/interface wifi datapath
add bridge=bridge disabled=no name=datapath1
add bridge=bridge_guest_vlan disabled=no name=datapath_guest vlan-id=20
/interface wifi security
add authentication-types=wpa2-psk,wpa3-psk connect-priority=0/1 \
    disable-pmkid=yes disabled=no ft=yes ft-over-ds=yes \
    management-protection=allowed name=sec1 sae-pwe=both wps=disable
/interface wifi configuration
add channel=ch_2ghz country=Germany datapath=datapath_guest disabled=no \
    multicast-enhance=enabled name=cfg_wifi_guest security=sec1 \
    security.authentication-types=wpa2-psk,wpa3-psk .disable-pmkid=yes .ft=\
    yes .ft-over-ds=yes .management-protection=allowed .wps=disable ssid=\
    guest_ihwip station-roaming=yes
add channel=ch_5g_fixed country=Germany datapath=datapath_guest disabled=no \
    installation=indoor mode=ap multicast-enhance=enabled name=\
    cfg_wifi_guest_5g security=sec1 security.authentication-types=\
    wpa2-psk,wpa3-psk ssid=guest_ihwip station-roaming=yes
/interface wifi steering
add disabled=no name=steering1 neighbor-group=\
    dynamic-It_hurts_when_IP-1a511a4c rrm=yes wnm=yes
/interface wifi configuration
add channel=ch_2ghz country=Germany datapath=datapath1 datapath.bridge=bridge \
    disabled=no installation=indoor mode=ap multicast-enhance=enabled name=\
    cfg_wifi security=sec1 security.authentication-types=wpa2-psk \
    .connect-priority=0/1 .ft=yes .ft-over-ds=yes ssid=It_hurts_when_IP \
    station-roaming=yes steering=steering1 steering.neighbor-group=\
    dynamic-It_hurts_when_IP-1a511a4c .rrm=yes .wnm=yes tx-power=20
add channel=ch_5g_fixed country=Germany datapath=datapath1 datapath.bridge=\
    bridge disabled=no installation=indoor mode=ap multicast-enhance=enabled \
    name=cfg_wifi_5g security=sec1 security.authentication-types=wpa2-psk \
    .ft=yes .ft-over-ds=yes ssid=It_hurts_when_IP station-roaming=yes \
    steering=steering1 steering.neighbor-group=\
    dynamic-It_hurts_when_IP-1a511a4c .rrm=yes .wnm=yes tx-power=23
/interface wifi
set [ find default-name=wifi2 ] configuration=cfg_wifi configuration.country=\
    Germany .installation=indoor .mode=ap .ssid=It_hurts_when_IP .tx-power=20 \
    disabled=no name=wifi_2ghz security=sec1 security.authentication-types=\
    wpa2-psk,wpa3-psk .ft=yes .ft-over-ds=yes steering=steering1 \
    steering.neighbor-group=dynamic-It_hurts_when_IP-1a511a4c .rrm=yes .wnm=\
    yes
set [ find default-name=wifi1 ] channel=ch_5g_fixed channel.band=5ghz-ax \
    .skip-dfs-channels=all configuration=cfg_wifi_5g configuration.chains=0,1 \
    .country=Germany .installation=indoor .mode=ap .multicast-enhance=enabled \
    .ssid=It_hurts_when_IP .tx-chains=0,1 .tx-power=23 disabled=no name=\
    wifi_5ghz security=sec1 security.authentication-types=wpa2-psk,wpa3-psk \
    .disable-pmkid=yes .ft=yes .ft-over-ds=yes .wps=disable steering=\
    steering1 steering.neighbor-group=dynamic-It_hurts_when_IP-1a511a4c .rrm=\
    yes .wnm=yes
add configuration=cfg_wifi_guest configuration.mode=ap mac-address=\
    xx:xx:xx:xx:xx:xx master-interface=wifi_2ghz name=wifi_guest \
    security.authentication-types=wpa2-psk,wpa3-psk .disable-pmkid=yes
/interface vlan
add interface=wifi_guest name=guest_vlan20 vlan-id=20
/ip pool
add name=default-dhcp ranges=192.168.88.10-192.168.88.254
add name=dhcp_pool1 ranges=10.10.10.2-10.10.10.254
/ip dhcp-server
add address-pool=default-dhcp interface=bridge name=defconf
add address-pool=dhcp_pool1 interface=bridge_guest_vlan name=dhcp_guest
/queue type
add kind=pcq name=pcq-upload-guest pcq-classifier=src-address pcq-limit=20KiB \
    pcq-rate=5M pcq-total-limit=200KiB
add kind=pcq name=pcq-download-guest pcq-classifier=dst-address pcq-limit=\
    20KiB pcq-rate=20M pcq-total-limit=200KiB
set 7 pcq-limit=20KiB pcq-rate=300M pcq-total-limit=500KiB
set 8 pcq-limit=20KiB pcq-rate=600M pcq-total-limit=500KiB
/ppp profile
set *0 queue-type=pcq-upload-default/pcq-download-default rate-limit=""
set *FFFFFFFE queue-type=pcq-upload-default/pcq-download-default rate-limit=\
    ""
/queue simple
add limit-at=300M/600M max-limit=300M/600M name="Full speed" queue=\
    pcq-upload-default/pcq-download-default target=bridge,bridge_guest_vlan
add limit-at=300M/600M max-limit=300M/600M name="Internal users" parent=\
    "Full speed" priority=1/1 queue=pcq-upload-default/pcq-download-default \
    target=bridge
add limit-at=5M/20M max-limit=5M/20M name=Guest parent="Full speed" queue=\
    pcq-upload-guest/pcq-download-guest target=bridge_guest_vlan
/system script
add comment=defconf dont-require-permissions=no name=dark-mode owner=*sys \
    policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon \
    source="\r\
    \n   :if ([system leds settings get all-leds-off] = \"never\") do={\r\
    \n     /system leds settings set all-leds-off=immediate \r\
    \n   } else={\r\
    \n     /system leds settings set all-leds-off=never \r\
    \n   }\r\
    \n "
add comment=defconf dont-require-permissions=no name=wps-accept owner=*sys \
    policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon \
    source="\r\
    \n   :foreach iface in=[/interface/wifi find where (configuration.mode=\"a\
    p\" && disabled=no)] do={\r\
    \n     /interface/wifi wps-push-button \$iface;}\r\
    \n "
/disk settings
set auto-media-interface=bridge
/interface bridge port
add bridge=bridge comment=defconf interface=ether2
add bridge=bridge comment=defconf interface=ether3
add bridge=bridge comment=defconf interface=ether4
add bridge=bridge comment=defconf interface=ether5
add bridge=bridge comment=defconf interface=wifi_5ghz
add bridge=bridge comment=defconf interface=wifi_2ghz
add bridge=bridge_guest_vlan interface=guest_vlan20
/ip neighbor discovery-settings
set discover-interface-list=LAN
/ip settings
set tcp-syncookies=yes
/ipv6 settings
set max-neighbor-entries=15360
/interface list member
add comment=defconf interface=bridge list=LAN
add comment=defconf interface=ether1 list=WAN
add interface=telekom_pppoe-out1 list=WAN
add interface=telekom_vlan list=WAN
add interface=bridge_guest_vlan list=LAN
/interface mesh port
add interface=*22 mesh=*23
add interface=*21 mesh=*23
/interface ovpn-server server
add mac-address=xx:xx:xx:xx:xx:xx name=ovpn-server1
/interface wifi capsman
set enabled=yes package-path="" require-peer-certificate=no upgrade-policy=\
    require-same-version
/interface wifi provisioning
add action=create-dynamic-enabled disabled=no master-configuration=cfg_wifi \
    name-format=cap-%I-wifi2g supported-bands=2ghz-ax
add action=create-dynamic-enabled disabled=no master-configuration=\
    cfg_wifi_5g name-format=cap-%I-wifi5g supported-bands=5ghz-ax
add action=create-dynamic-enabled disabled=no master-configuration=\
    cfg_wifi_guest name-format=cap-%I-guest2g supported-bands=2ghz-ax
add action=create-dynamic-enabled disabled=no master-configuration=\
    cfg_wifi_guest_5g name-format=cap-%I-guest5g supported-bands=5ghz-ax
/ip address
add address=192.168.88.1/24 comment=defconf interface=bridge network=\
    192.168.88.0
add address=10.10.10.1/24 interface=bridge_guest_vlan network=10.10.10.0
/ip dhcp-server lease
add address=192.168.88.250 client-id=1:xx:xx:xx:xx:xx:xx mac-address=\
    xx:xx:xx:xx:xx:xx server=defconf
add address=192.168.88.243 mac-address=xx:xx:xx:xx:xx:xx server=defconf
add address=192.168.88.247 client-id=1:xx:xx:xx:xx:xx:xx mac-address=\
    xx:xx:xx:xx:xx:xx server=defconf
add address=192.168.88.209 client-id=1:xx:xx:xx:xx:xx:xx mac-address=\
    xx:xx:xx:xx:xx:xx server=defconf
/ip dhcp-server network
add address=10.10.10.0/24 dns-server=10.10.10.1 gateway=10.10.10.1
add address=192.168.88.0/24 comment=defconf dns-server=192.168.88.1 gateway=\
    192.168.88.1
/ip dns
set cache-size=4096KiB servers=xxx.xxx.xxx.xxx,xxx.xxx.xxx.xxx,2620:fe::fe,2620:fe::9
/ip dns static
add address=192.168.88.1 comment=defconf name=router.lan type=A
add address=xxx.xxx.xxx.xxx name=annas-archive.org type=A
/ip firewall address-list
add address=xxx.xxx.xxx.xxx/8 comment="defconf: RFC6890" list=no_forward_ipv4
add address=xxx.xxx.xxx.xxx/16 comment="defconf: RFC6890" list=no_forward_ipv4
add address=xxx.xxx.xxx.xxx comment="defconf: RFC6890" list=no_forward_ipv4
add address=xxx.xxx.xxx.xxx/8 comment="defconf: RFC6890" list=bad_ipv4
add address=xxx.xxx.xxx.xxx/24 comment="defconf: RFC6890" list=bad_ipv4
add address=xxx.xxx.xxx.xxx/24 comment="defconf: RFC6890 documentation" list=\
    bad_ipv4
add address=xxx.xxx.xxx.xxx/24 comment="defconf: RFC6890 documentation" list=\
    bad_ipv4
add address=xxx.xxx.xxx.xxx/24 comment="defconf: RFC6890 documentation" list=\
    bad_ipv4
add address=xxx.xxx.xxx.xxx/4 comment="defconf: RFC6890 reserved" list=bad_ipv4
add address=xxx.xxx.xxx.xxx/8 comment="defconf: RFC6890" list=not_global_ipv4
add address=10.0.0.0/8 comment="defconf: RFC6890" list=not_global_ipv4
add address=xxx.xxx.xxx.xxx/10 comment="defconf: RFC6890" list=not_global_ipv4
add address=xxx.xxx.xxx.xxx/16 comment="defconf: RFC6890" list=not_global_ipv4
add address=172.16.0.0/12 comment="defconf: RFC6890" list=not_global_ipv4
add address=xxx.xxx.xxx.xxx/29 comment="defconf: RFC6890" list=not_global_ipv4
add address=192.168.0.0/16 comment="defconf: RFC6890" list=not_global_ipv4
add address=xxx.xxx.xxx.xxx/15 comment="defconf: RFC6890 benchmark" list=\
    not_global_ipv4
add address=xxx.xxx.xxx.xxx comment="defconf: RFC6890" list=not_global_ipv4
add address=xxx.xxx.xxx.xxx/4 comment="defconf: multicast" list=bad_src_ipv4
add address=xxx.xxx.xxx.xxx comment="defconf: RFC6890" list=bad_src_ipv4
add address=xxx.xxx.xxx.xxx/8 comment="defconf: RFC6890" list=bad_dst_ipv4
add address=xxx.xxx.xxx.xxx/4 comment="defconf: RFC6890" list=bad_dst_ipv4
add address=192.168.88.0/24 list=allowed_local_subnets
add address=10.10.10.0/24 list=allowed_local_subnets
/ip firewall filter
add action=fasttrack-connection chain=forward comment="FastTrack IPv4" \
    connection-state=established,related
add action=accept chain=input comment="Allow Guest DNS to router" dst-port=53 \
    in-interface=bridge_guest_vlan protocol=udp src-address=10.10.10.0/24
add action=accept chain=input comment="Allow Guest DNS TCP to router" \
    dst-port=53 in-interface=bridge_guest_vlan protocol=tcp src-address=\
    10.10.10.0/24
add action=accept chain=forward comment=\
    "defconf: accept established,related, untracked" connection-state=\
    established,related,untracked
add action=accept chain=input connection-state=established
add action=accept chain=input connection-state=related
add action=drop chain=forward comment="defconf: drop invalid" \
    connection-state=invalid
add action=drop chain=forward comment="defconf: drop bad forward IPs" \
    dst-address-list=no_forward_ipv4
add action=drop chain=input comment="Block guest to router" src-address=\
    10.10.10.0/24
add action=accept chain=forward comment="defconf: accept in ipsec policy" \
    ipsec-policy=in,ipsec
add action=accept chain=forward comment="defconf: accept out ipsec policy" \
    ipsec-policy=out,ipsec
add action=accept chain=input protocol=icmp
add action=drop chain=forward comment="Block guest access" dst-address=\
    192.168.88.0/24 src-address=10.10.10.0/24
add action=drop chain=forward comment=\
    "defconf: drop all from WAN not DSTNATed" connection-nat-state=!dstnat \
    connection-state=new in-interface-list=WAN
add action=drop chain=input in-interface-list=!LAN
add action=drop chain=input comment="Drop DNS requests outside of network" \
    dst-port=53 protocol=udp src-address=!192.168.88.0/24
add action=drop chain=input dst-port=53 protocol=tcp src-address=\
    !192.168.88.0/24
add action=drop chain=forward comment="defconf: drop bad forward IPs" \
    src-address-list=no_forward_ipv4
add action=return chain=detect-ddos dst-limit=32,32,src-and-dst-addresses/10s \
    protocol=tcp tcp-flags=syn,ack
/ip firewall mangle
add action=change-mss chain=forward comment="IPv4 MSS clamp outbound" \
    new-mss=1452 out-interface=telekom_pppoe-out1 protocol=tcp tcp-flags=syn
/ip firewall nat
add action=masquerade chain=srcnat comment="defconf: masquerade" \
    ipsec-policy=out,none out-interface=telekom_pppoe-out1 \
    out-interface-list=WAN
add action=redirect chain=dstnat comment="DNS redirect" dst-port=53 \
    in-interface=bridge protocol=udp to-ports=53
add action=redirect chain=dstnat comment="DNS redirect TCP" dst-port=53 \
    in-interface=bridge protocol=tcp to-ports=53
add action=redirect chain=dstnat comment="DNS redirect Guest" dst-port=53 \
    in-interface=bridge_guest_vlan protocol=udp to-ports=53
add action=redirect chain=dstnat comment="DNS redirect Guest TCP" dst-port=53 \
    in-interface=bridge_guest_vlan protocol=tcp to-ports=53
/ip firewall raw
add action=accept chain=prerouting comment=\
    "defconf: enable for transparent firewall" disabled=yes
add action=accept chain=prerouting comment="defconf: accept DHCP discover" \
    dst-address=xxx.xxx.xxx.xxx dst-port=67 in-interface-list=LAN protocol=\
    udp src-address=xxx.xxx.xxx.xxx src-port=68
add action=drop chain=prerouting comment="defconf: drop bogon IP's" \
    src-address-list=bad_ipv4
add action=drop chain=prerouting comment="defconf: drop bogon IP's" \
    dst-address-list=bad_ipv4
add action=drop chain=prerouting comment="defconf: drop bogon IP's" \
    src-address-list=bad_src_ipv4
add action=drop chain=prerouting comment="defconf: drop bogon IP's" \
    dst-address-list=bad_dst_ipv4
add action=drop chain=prerouting comment="defconf: drop non global from WAN" \
    in-interface-list=WAN src-address-list=not_global_ipv4
add action=drop chain=prerouting comment=\
    "defconf: drop forward to local lan from WAN" dst-address=192.168.88.0/24 \
    in-interface-list=WAN
add action=drop chain=prerouting comment=\
    "defconf: drop local if not from default IP range" in-interface-list=LAN \
    src-address-list=!allowed_local_subnets
add action=drop chain=prerouting comment="defconf: drop bad UDP" port=0 \
    protocol=udp
add action=jump chain=prerouting comment="defconf: jump to ICMP chain" \
    jump-target=icmp4 protocol=icmp
add action=jump chain=prerouting comment="defconf: jump to TCP chain" \
    jump-target=bad_tcp protocol=tcp
add action=accept chain=prerouting comment=\
    "defconf: accept everything else from LAN" in-interface-list=LAN
add action=accept chain=prerouting comment=\
    "defconf: accept everything else from WAN" in-interface-list=WAN
add action=drop chain=prerouting comment="defconf: drop the rest"
add action=drop chain=bad_tcp comment="defconf: TCP flag filter" protocol=tcp \
    tcp-flags=!fin,!syn,!rst,!ack
add action=drop chain=bad_tcp comment=defconf protocol=tcp tcp-flags=fin,syn
add action=drop chain=bad_tcp comment=defconf protocol=tcp tcp-flags=fin,rst
add action=drop chain=bad_tcp comment=defconf protocol=tcp tcp-flags=fin,!ack
add action=drop chain=bad_tcp comment=defconf protocol=tcp tcp-flags=fin,urg
add action=drop chain=bad_tcp comment=defconf protocol=tcp tcp-flags=syn,rst
add action=drop chain=bad_tcp comment=defconf protocol=tcp tcp-flags=rst,urg
add action=drop chain=bad_tcp comment="defconf: TCP port 0 drop" port=0 \
    protocol=tcp
/ip service
set ftp disabled=yes
set ssh disabled=yes
set telnet disabled=yes
set www address=192.168.88.0/24
set winbox address=192.168.88.0/24
set api address=192.168.88.0/24
set api-ssl address=192.168.88.0/24
/ip ssh
set strong-crypto=yes
/ipv6 address
add from-pool=tkom interface=bridge
/ipv6 dhcp-client
add add-default-route=yes interface=telekom_pppoe-out1 pool-name=tkom \
    pool-prefix-length=64 request=prefix use-peer-dns=no
/ipv6 firewall address-list
add address=::/128 comment="defconf: unspecified address" list=bad_ipv6
add address=::1/128 comment="defconf: lo" list=bad_ipv6
add address=fec0::/10 comment="defconf: site-local" list=bad_ipv6
add address=::ffff:xxx.xxx.xxx.xxx/96 comment="defconf: ipv4-mapped" list=bad_ipv6
add address=::/96 comment="defconf: ipv4 compat" list=bad_ipv6
add address=100::/64 comment="defconf: discard only " list=bad_ipv6
add address=2001:db8::/32 comment="defconf: documentation" list=bad_ipv6
add address=2001:10::/28 comment="defconf: ORCHID" list=bad_ipv6
add address=3ffe::/16 comment="defconf: 6bone" list=bad_ipv6
add address=2001::/23 comment="defconf: RFC6890" list=bad_ipv6
add address=100::/64 comment="defconf: RFC6890 Discard-only" list=\
    not_global_ipv6
add address=2001::/32 comment="defconf: RFC6890 TEREDO" list=not_global_ipv6
add address=2001:2::/48 comment="defconf: RFC6890 Benchmark" list=\
    not_global_ipv6
add address=fc00::/7 comment="defconf: RFC6890 Unique-Local" list=\
    not_global_ipv6
add address=::/128 comment="defconf: unspecified" list=bad_dst_ipv6
add address=::/128 comment="defconf: unspecified" list=bad_src_ipv6
add address=ff00::/8 comment="defconf: multicast" list=bad_src_ipv6
/ipv6 firewall filter
add action=fasttrack-connection chain=forward comment="FastTrack IPv6" \
    connection-state=established,related
add action=accept chain=input comment=\
    "defconf: accept established,related,untracked" connection-state=\
    established,related,untracked
add action=accept chain=input comment="defconf: accept ICMPv6" protocol=\
    icmpv6
add action=accept chain=forward comment="defconf: accept ICMPv6" protocol=\
    icmpv6
add action=drop chain=input comment="defconf: drop invalid" connection-state=\
    invalid
add action=accept chain=input comment="defconf: accept UDP traceroute" \
    dst-port=33434-33534 protocol=udp
add action=accept chain=input comment=\
    "defconf: accept DHCPv6-Client prefix delegation." dst-port=546 protocol=\
    udp src-address=fe80::/16
add action=accept chain=input comment="defconf: accept IKE" dst-port=500,4500 \
    protocol=udp
add action=accept chain=input comment="defconf: accept ipsec AH" protocol=\
    ipsec-ah
add action=accept chain=input comment="defconf: accept ipsec ESP" protocol=\
    ipsec-esp
add action=accept chain=input comment=\
    "defconf: accept all that matches ipsec policy" ipsec-policy=in,ipsec
add action=drop chain=input comment="Drop IPv6 guest input to router" \
    in-interface=bridge_guest_vlan
add action=accept chain=input comment="Allow guest DNS IPv6" dst-port=53 \
    in-interface=bridge_guest_vlan protocol=udp
add action=accept chain=input comment="Allow guest DNS TCP IPv6" dst-port=53 \
    in-interface=bridge_guest_vlan protocol=tcp
add action=drop chain=input comment=\
    "defconf: drop everything else not coming from LAN" in-interface-list=\
    !LAN
add action=accept chain=forward comment=\
    "defconf: accept established,related,untracked" connection-state=\
    established,related,untracked
add action=drop chain=forward comment="defconf: drop invalid" \
    connection-state=invalid
add action=drop chain=forward comment=\
    "defconf: drop packets with bad src ipv6" src-address-list=bad_ipv6
add action=drop chain=forward comment=\
    "defconf: drop packets with bad dst ipv6" dst-address-list=bad_ipv6
add action=drop chain=forward comment="defconf: rfc4890 drop hop-limit=1" \
    disabled=yes hop-limit=equal:1 protocol=icmpv6
add action=accept chain=forward comment="defconf: accept HIP" protocol=139
add action=accept chain=forward comment="defconf: accept IKE" dst-port=\
    500,4500 protocol=udp
add action=accept chain=forward comment="accept UDP traceroute" dst-port=\
    33434-33534 protocol=udp
add action=accept chain=forward comment="defconf: accept ipsec AH" protocol=\
    ipsec-ah
add action=accept chain=forward comment="defconf: accept ipsec ESP" protocol=\
    ipsec-esp
add action=accept chain=forward comment=\
    "defconf: accept all that matches ipsec policy" ipsec-policy=in,ipsec
add action=drop chain=forward comment="Block IPv6 guest to LAN" in-interface=\
    bridge_guest_vlan out-interface=bridge
add action=drop chain=forward comment=\
    "defconf: drop everything else not coming from LAN" in-interface-list=\
    !LAN
/ipv6 firewall mangle
add action=change-mss chain=forward comment="IPv6 MSS clamp outbound" \
    new-mss=1432 out-interface=telekom_pppoe-out1 protocol=tcp tcp-flags=syn
/ipv6 firewall raw
add action=accept chain=prerouting comment=\
    "defconf: enable for transparent firewall"
add action=accept chain=prerouting comment="defconf: RFC4291, section 2.7.1" \
    dst-address=ff02::1:ff00:0/104 icmp-options=135:0-255 protocol=icmpv6 \
    src-address=::/128
add action=drop chain=prerouting comment="defconf: drop bogon IP's" \
    src-address-list=bad_ipv6
add action=drop chain=prerouting comment="defconf: drop bogon IP's" \
    dst-address-list=bad_ipv6
add action=drop chain=prerouting comment=\
    "defconf: drop packets with bad SRC ipv6" src-address-list=bad_src_ipv6
add action=drop chain=prerouting comment=\
    "defconf: drop packets with bad dst ipv6" dst-address-list=bad_dst_ipv6
add action=drop chain=prerouting comment="defconf: drop non global from WAN" \
    in-interface-list=WAN src-address-list=not_global_ipv6
add action=jump chain=prerouting comment="defconf: jump to ICMPv6 chain" \
    jump-target=icmp6 protocol=icmpv6
add action=accept chain=prerouting comment=\
    "defconf: accept local multicast scope" dst-address=ff02::/16
add action=drop chain=prerouting comment=\
    "defconf: drop other multicast destinations" dst-address=ff00::/8
add action=accept chain=prerouting comment=\
    "defconf: accept everything else from WAN" in-interface-list=WAN
add action=accept chain=prerouting comment=\
    "defconf: accept everything else from LAN" in-interface-list=LAN
add action=drop chain=prerouting comment="defconf: drop the rest"
/ipv6 nd
set [ find default=yes ] advertise-dns=yes interface=bridge
/system clock
set time-zone-name=Europe/Berlin
/system leds settings
set all-leds-off=after-1min
/system ntp client
set enabled=yes
/system ntp client servers
add address=de.pool.ntp.org
/system routerboard mode-button
set enabled=yes on-event=dark-mode
/system routerboard wps-button
set enabled=yes on-event=wps-accept
/system scheduler
add disabled=yes interval=1d name=reboot_daily policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon \
    start-date=2025-07-02 start-time=04:30:00
/tool mac-server
set allowed-interface-list=LAN
/tool mac-server mac-winbox
set allowed-interface-list=LAN
