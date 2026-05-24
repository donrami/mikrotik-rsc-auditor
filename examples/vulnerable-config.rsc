# Vulnerable config — deliberately insecure for demo/testing
# RouterOS 6.49.6 — hAP ac²
/interface bridge
add name=bridge
/interface list
add name=WAN
add name=LAN
/interface list member
add interface=ether1 list=WAN
add interface=bridge list=LAN
/ip address
add address=192.168.88.1/24 interface=bridge
/ip service
set ftp disabled=no
set telnet disabled=no
set www disabled=no address=0.0.0.0/0
set winbox disabled=no address=0.0.0.0/0
set api disabled=no address=0.0.0.0/0
/ip ssh
set strong-crypto=no forwarding-enabled=yes
/ip dns
set allow-remote-requests=yes servers=8.8.8.8
/snmp community
set public name=public address=0.0.0.0/0
/ip upnp
set enabled=yes
/tool bandwidth-server
set enabled=yes
/ip socks
set enabled=yes
/ip proxy
set enabled=yes
/romon
set enabled=yes
/ip cloud
set ddns-enabled=yes
/ip neighbor discovery-settings
set discover-interface-list=all
/tool mac-server
set allowed-interface-list=all
/tool mac-server mac-winbox
set allowed-interface-list=all
/interface wireless security-profile
set default authentication-types=wep-psk wpa2-pre-shared-key=12345678 mode=dynamic-keys
/interface wireless
set wlan1 wps-mode=push-button mode=ap-bridge ssid=InsecureNet security-profile=default
