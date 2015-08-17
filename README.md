# pr0cks
python script to transparently forward all TCP and DNS traffic through a socks4/socks5/HTTP_CONNECT proxy (like ssh -D) using iptables -j REDIRECT target
## Features :
- set up a local transparent proxy compatible with socks4 socks5 and HTTP CONNECT proxies allowing to forward any TCP traffic transparently using iptables
- set up a local transparent DNS proxy translating UDP port 53 requests to TCP allowing DNS traffic to go through a proxy without UDP support (like ssh -D option)
- DNS caching mechanism to speed up the DNS resolutions through pr0cks

# example: let's rock
As an example we will use the socks5 proxy of openssh (the option -D)
```bash
$ ssh -D 1080 user@sshserver
```
then you can add some iptables rules :
```bash
$ iptables -t nat -A OUTPUT ! -d <my_ssh_server_IP>/32 -o eth0 -p tcp -m tcp -j REDIRECT --to-ports 10080
$ iptables -t nat -A OUTPUT -o eth0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 1053
```
then start pr0cks :
```bash
$ python pr0cks.py --proxy SOCKS5:127.0.0.1:1080
```
All your TCP trafic and DNS traffic should now pass through the ssh server kinda like if you had setup a tun VPN through ssh but without admin rights on the server !
#help
```text
python pr0cks.py -h
usage: procks [-h] [--proxy PROXY] [-p PORT] [-v] [--username USERNAME]
              [--password PASSWORD] [--dns-port DNS_PORT]
              [--dns-server DNS_SERVER]

Transparent SOCKS5/SOCKS4/HTTP_CONNECT Proxy

optional arguments:
  -h, --help            show this help message and exit
  --proxy PROXY         proxytype:ip:port to forward our connections through.
                        proxytype can be SOCKS5, SOCKS4 or HTTP
  -p PORT, --port PORT  port to bind the transparent proxy on the local socket
                        (default 10080)
  -v, --verbose         print all the connections requested through the proxy
  --username USERNAME   Username to authenticate with to the server. The
                        default is no authentication.
  --password PASSWORD   Only relevant when a username has been provided
  --dns-port DNS_PORT   dns port to listen on (default 1053)
  --dns-server DNS_SERVER
                        ip:port of the DNS server to forward all DNS requests
                        to using TCP through the proxy (default
                        208.67.222.222:53)
```
# TODO
- support UDP (with socks5)
- support proxy chaining

