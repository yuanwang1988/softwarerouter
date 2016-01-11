# Software Router with Network Address Translation

In this project, we implement a software router with Network Address Translation functionality in C. More specifically, we implemented the following functionality:

Basic router
- Initiate and respond to ARP requests in order to discover MAC addresses of connected machines.
- Maintain ARP Cache.
- Route ICMP and IP packets (perform consistency checks on incoming packets before forwarding).

Network Address Translation (NAT):
- Build and maintain a NAT table in order to translate local IP and port number to external IP and port number.
- Modify the IP address and ICMP ID / port number of incoming packets based on NAT table.
- Maintain the TCP state of each TCP connection based on packets passing through the router in order to determine when it is safe to remove a NAT mapping in the NAT table.