"""Sample input for the config import: the demo HQ network as Cisco IOS output
(show running-config + show cdp neighbors), endpoints and required flows.
The firewall is an IOS equivalent; it is not a FortiOS configuration export."""

CONFIGS = """\
FW1#show running-config
hostname FW1
!
interface GigabitEthernet0/0/0
 description WAN to ISP
 ip address 203.0.113.2 255.255.255.252
!
interface GigabitEthernet0/0/1
 description LAN to R1
 ip address 10.0.1.1 255.255.255.252
!
ip route 0.0.0.0 0.0.0.0 203.0.113.1
ip route 10.0.0.0 255.0.0.0 10.0.1.2
ip route 192.168.30.0 255.255.255.0 10.0.1.2
end

R1#show running-config
hostname R1
!
interface GigabitEthernet0/0/0
 ip address 10.0.12.1 255.255.255.252
!
interface GigabitEthernet0/0/1
 ip address 10.0.13.1 255.255.255.252
!
interface GigabitEthernet0/0/2
 ip address 10.0.1.2 255.255.255.252
!
interface GigabitEthernet0/1/0
 no ip address
 shutdown
!
router ospf 1
 network 10.0.12.0 0.0.0.3 area 0
 network 10.0.13.0 0.0.0.3 area 0
!
ip route 0.0.0.0 0.0.0.0 10.0.1.1
end

R1#show cdp neighbors
Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge
                  S - Switch, H - Host, I - IGMP, r - Repeater, P - Phone
Device ID    Local Intrfce   Holdtme    Capability   Platform    Port ID
R2           Gig 0/0/0          163            R       ISR4300     Gig 0/0/0
R3           Gig 0/0/1          171            R       ISR4300     Gig 0/0/0
FW1          Gig 0/0/2          150            R       ISR4300     Gig 0/0/1

R2#show running-config
hostname R2
!
interface GigabitEthernet0/0/0
 ip address 10.0.12.2 255.255.255.252
!
interface GigabitEthernet0/0/1
 no ip address
!
interface GigabitEthernet0/0/1.10
 encapsulation dot1Q 10
 ip address 10.20.0.1 255.255.255.0
!
interface GigabitEthernet0/0/1.20
 encapsulation dot1Q 20
 ip address 10.21.0.1 255.255.255.0
 ip access-group 110 in
!
router ospf 1
 network 10.0.12.0 0.0.0.3 area 0
 network 10.20.0.0 0.0.0.255 area 0
 network 10.21.0.0 0.0.0.255 area 0
!
access-list 110 deny ip 10.21.0.0 0.0.0.255 10.20.0.0 0.0.0.255
access-list 110 permit ip any any
end

R2#show cdp neighbors
Device ID    Local Intrfce   Holdtme    Capability   Platform    Port ID
R1           Gig 0/0/0          163            R       ISR4300     Gig 0/0/0
SW1          Gig 0/0/1          158            S       2960X       Gig 1/0/24

R3#show running-config
hostname R3
!
interface GigabitEthernet0/0/0
 ip address 10.0.13.2 255.255.255.252
!
interface GigabitEthernet0/0/1
 ip address 192.168.30.1 255.255.255.0
 ip access-group PROTECT-SERVERS out
!
router ospf 1
 network 10.0.13.0 0.0.0.3 area 0
 network 192.168.30.0 0.0.0.255 area 0
!
ip access-list extended PROTECT-SERVERS
 100 permit ip any any
end

R3#show cdp neighbors
Device ID    Local Intrfce   Holdtme    Capability   Platform    Port ID
R1           Gig 0/0/0          171            R       ISR4300     Gig 0/0/1
SW2          Gig 0/0/1          140            S       2960X       Gig 1/0/24

SW1#show running-config
hostname SW1
!
vlan 10
 name FINANCE
vlan 20
 name HR
!
interface GigabitEthernet1/0/24
 switchport mode trunk
!
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 20
!
interface GigabitEthernet1/0/3
!
interface Vlan1
 ip address 192.168.1.11 255.255.255.0
end

SW2#show running-config
hostname SW2
!
vlan 30
 name SERVERS
!
interface GigabitEthernet1/0/24
 switchport mode access
 switchport access vlan 30
!
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 30
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 30
!
interface Vlan1
 ip address 192.168.1.12 255.255.255.0
end
"""

ENDPOINTS = """\
# name, type, ip/prefix, gateway, connected to (device interface)
INTERNET, internet, 203.0.113.1/30, , FW1 Gi0/0/0
Finance-PC, pc, 10.20.0.10/24, 10.20.0.1, SW1 Gi1/0/1
HR-PC, pc, 10.21.0.10/24, 10.21.0.1, SW1 Gi1/0/2
ERP, server, 192.168.30.10/24, 192.168.30.1, SW2 Gi1/0/1
DNS, server, 192.168.30.53/24, 192.168.30.1, SW2 Gi1/0/2
"""

FLOWS = """\
# name, source, destination, protocol, port, allow|deny, criticality
Finance ERP access (HTTPS), Finance-PC, ERP, tcp, 443, allow, critical
HR ERP access (HTTPS), HR-PC, ERP, tcp, 443, allow, high
Finance DNS resolution, Finance-PC, DNS, udp, 53, allow, medium
HR DNS resolution, HR-PC, DNS, udp, 53, allow, medium
HR / Finance isolation, HR-PC, Finance-PC, ip, , deny, high
Finance Internet access (HTTPS), Finance-PC, INTERNET, tcp, 443, allow, high
"""
