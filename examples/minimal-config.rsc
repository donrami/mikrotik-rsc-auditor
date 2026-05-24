# Minimal secure config — baseline for testing
# RouterOS 7.22.3 — hAP ax³
/interface bridge
add admin-mac=xx:xx:xx:xx:xx:01 auto-mac=no name=bridge
/interface list
add name=WAN
add name=LAN
/interface list member
add interface=ether1 list=WAN
add interface=bridge list=LAN
/ip address
add address=192.168.88.1/24 interface=bridge
/ip dhcp-server
add address-pool=default-dhcp interface=bridge name=defconf
/ip pool
add name=default-dhcp ranges=192.168.88.10-192.168.88.254
/ip dhcp-server network
add address=192.168.88.0/24 dns-server=192.168.88.1 gateway=192.168.88.1
/ip dns
set cache-size=2048KiB servers=9.9.9.9,149.112.112.9
/ip firewall filter
add action=fasttrack-connection chain=forward connection-state=established,related
add action=accept chain=input connection-state=established,related
add action=accept chain=forward connection-state=established,related
add action=drop chain=input connection-state=invalid
add action=drop chain=forward connection-state=invalid
add action=accept chain=input protocol=icmp
add action=drop chain=input in-interface-list=!LAN
add action=drop chain=forward in-interface-list=WAN connection-nat-state=!dstnat connection-state=new
/ip firewall nat
add action=masquerade chain=srcnat out-interface-list=WAN
/ip service
set ftp disabled=yes
set ssh disabled=no address=192.168.88.0/24
set telnet disabled=yes
set www disabled=yes
set winbox address=192.168.88.0/24
/ip ssh
set strong-crypto=yes
/tool mac-server
set allowed-interface-list=LAN
/tool mac-server mac-winbox
set allowed-interface-list=LAN
/ip neighbor discovery-settings
set discover-interface-list=LAN
/system ntp client
set enabled=yes
/system ntp client servers
add address=de.pool.ntp.org
/system clock
set time-zone-name=Europe/Berlin
/system identity
set name=minimal-router
/ip dns static
add address=192.168.88.1 name=router.lan type=A
