# Author: Nicolas VERDIER
# This file is part of pr0cks.
#
# pr0cks is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# pr0cks is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pr0cks.  If not, see <http://www.gnu.org/licenses/>.

import sys
import StringIO
import time
import struct
import os
import asyncore
import socket
import socks
import argparse
import traceback
import logging
import binascii
from collections import OrderedDict

dnslib_imported=False
dns_cache=OrderedDict()
DNS_CACHE_SIZE=1000

def display(msg):
    msg=msg.strip()
    if msg.startswith("[-]"):
        print "\033[31m[-]\033[0m"+msg[3:]
    elif msg.startswith("[+]"):
        print "\033[32m[+]\033[0m"+msg[3:]
    elif msg.startswith("[i]"):
        print "\033[1;30m[i]\033[0m"+msg[3:]
    else:
        print msg

try:
    from dnslib import DNSRecord
    from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger
    class ProxyResolver(BaseResolver):
        def __init__(self,address,port):
            self.address = address
            self.port = port

        def resolve(self,request,handler):
            if handler.protocol == 'udp':
                proxy_r = request.send(self.address,self.port)
            else:
                proxy_r = request.send(self.address,self.port,tcp=True)
            reply = DNSRecord.parse(proxy_r)
            return reply

    class PassthroughDNSHandler(DNSHandler):
        def get_reply(self,data):
            global dns_cache
            global args
            host,port = self.server.resolver.address,self.server.resolver.port
            request = DNSRecord.parse(data)

            domain=str(request.q.qname)
            if domain in dns_cache:
                if time.time()<dns_cache[domain][0]:
                    if args is not None and args.verbose:
                        display("[i] domain %s served from cache"%domain)
                    rep=request.reply()
                    rep.add_answer(*dns_cache[domain][1])
                    return rep.pack()
            if args is not None and args.verbose:
                display("[i] domain %s requested using TCP server %s"%(domain, args.dns_server))
            data = struct.pack("!H",len(data)) + data
            response = send_tcp(data,host,port)
            response = response[2:]
            reply = DNSRecord.parse(response)
            #print(repr(reply))
            ttl=3600
            try:
                ttl=reply.rr[0].ttl
            except Exception:
                try:
                    ttl=reply.rr.ttl
                except Exception:
                    pass
            dns_cache[domain]=(int(time.time())+ttl, reply.rr)
            if len(dns_cache)>DNS_CACHE_SIZE:
                dns_cache.popitem(last=False)
            return response

    def send_tcp(data,host,port):
        """
            Helper function to send/receive DNS TCP request
            (in/out packets will have prepended TCP length header)
        """
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.connect((host,port))
        sock.sendall(data)
        response = sock.recv(8192)
        length = struct.unpack("!H",bytes(response[:2]))[0]
        while len(response) - 2 < length:
            response += sock.recv(8192)
        sock.close()
        return response
    dnslib_imported=True
except ImportError:
    display("[-] WARNING: The following dependency is needed to proxify DNS through tcp: pip install dnslib")


#Python socket module does not have this constant
SO_ORIGINAL_DST = 80
class Socks5Conn(asyncore.dispatcher):
    def __init__(self, sock=None, map=None, conn=True, verbose=False):
        self.out_buffer=b""
        self.verbose=verbose
        self.allsent=False
        if conn is True:
            #get the original dst address and port
            odestdata = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            _, port, a1, a2, a3, a4 = struct.unpack("!HHBBBBxxxxxxxx", odestdata)
            address = "%d.%d.%d.%d" % (a1, a2, a3, a4)
            if self.verbose:
                display('[+] Forwarding incoming connection from %s to %s through the proxy' % (repr(sock.getpeername()), (address, port)))
            #connect to the original dst :
            self.conn_sock = socks.socksocket()
            self.conn_sock.connect((address, port))

            self.sock_class=Socks5Conn(sock=self.conn_sock, conn=self) #add a dispatcher to handle the other side
        else:
            self.sock_class=conn
            self.conn_sock=None
        asyncore.dispatcher.__init__(self, sock, map)

    def initiate_send(self):
        num_sent = 0
        num_sent = asyncore.dispatcher.send(self, self.out_buffer[:2048])
        self.out_buffer = self.out_buffer[num_sent:]

    def handle_write(self):
        self.initiate_send()

    def writable(self):
        return (self.allsent or len(self.out_buffer)>0)

    def send(self, data):
        #if self.debug:
        #    self.log_info('sending %s' % repr(data))
        if data:
            self.out_buffer += data
        else:
            self.allsent=True
        #self.initiate_send()

    def handle_read(self):
        data = self.recv(8192)
        self.sock_class.send(data)

    def handle_close(self):
        self.close()



class Pr0cks5Server(asyncore.dispatcher):
    verbose=False
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(20)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            handler = Socks5Conn(sock, verbose=self.verbose)
    def handle_error(self):
        t, v, tb = sys.exc_info()
        display("[-] %s : %s"%(t,v))

        

args=None
if __name__=='__main__':
    parser = argparse.ArgumentParser(prog='procks', description="Transparent SOCKS5/SOCKS4/HTTP_CONNECT Proxy")
    parser.add_argument('--proxy', default="SOCKS5:127.0.0.1:1080", help="proxytype:ip:port to forward our connections through. proxytype can be SOCKS5, SOCKS4 or HTTP")
    parser.add_argument('-p', '--port', type=int, default=10080, help="port to bind the transparent proxy on the local socket (default 10080)")
    parser.add_argument('-n', '--nat', action='store_true', help="set bind address to 0.0.0.0 to make pr0cks work from a netfilter FORWARD rule instead of OUTPUT")
    parser.add_argument('-v', '--verbose', action="store_true", help="print all the connections requested through the proxy")
    parser.add_argument('--username', default=None, help="Username to authenticate with to the server. The default is no authentication.")
    parser.add_argument('--password', default=None, help="Only relevant when a username has been provided")
    parser.add_argument('--dns-port', default=1053, type=int, help="dns port to listen on (default 1053)")
    parser.add_argument('--dns-server', default="208.67.222.222:53", help="ip:port of the DNS server to forward all DNS requests to using TCP through the proxy (default 208.67.222.222:53)")
    args=parser.parse_args()

    bind_address="127.0.0.1"
    if args.nat:
        bind_address="0.0.0.0"
    if dnslib_imported:
        try:
            dns_srv, dns_port=args.dns_server.split(':',1)
            dns_port=int(dns_port)
        except Exception as e:
            display("[-] %s"%e)
            display("[-] Invalid dns server : %s"%args.dns_server)
            exit(1)
        resolver = ProxyResolver(dns_srv,dns_port)
        handler = PassthroughDNSHandler # if args.passthrough else DNSHandler
        logger = DNSLogger("request,reply,truncated,error", False)
        udp_server = DNSServer(resolver,
                               port=args.dns_port,
                               address=bind_address,
                               logger=logger,
                               handler=handler)
        udp_server.start_thread()
        display("[+] DNS server started on %s:%s forwarding all DNS trafic to %s:%s using TCP"%(bind_address, args.dns_port, dns_srv, dns_port))

    ptype,proxy_addr,proxy_port=args.proxy.split(":",2)
    t=None
    if ptype.upper()=="SOCKS5":
        t=socks.PROXY_TYPE_SOCKS5
    elif ptype.upper()=="SOCKS4":
        t=socks.PROXY_TYPE_SOCKS4
    elif ptype.upper()=="HTTP":
        t=socks.PROXY_TYPE_HTTP
    else:
        display("[-] --proxy : unknown proxy type %s"%ptype)
        exit(1)
    try:
        proxy_port=int(proxy_port)
    except Exception:
        display("[-] --proxy : invalid port %s"%proxy_port)
        exit(1)

    if args.username:
        if not args.password:
            exit("username provided but without password !")
        display("[+] Provided credentials are %s:%s"%(args.username, args.password[0:3]+"*"*(len(args.password)-3)))
    socks.setdefaultproxy(proxytype=t, addr=proxy_addr, port=proxy_port, username=args.username, password=args.password)

    display("[+] Forwarding all TCP traffic received on %s:%s through the %s proxy on %s:%s"%(bind_address, args.port, ptype, proxy_addr, proxy_port))
    display("[i] example of rule you need to have:")
    display("iptables -t nat -A OUTPUT -o eth0 -p tcp -m tcp !-d <proxy_server> -j REDIRECT --to-ports %s"%args.port)
    display("iptables -t nat -A OUTPUT -o eth0 -p udp -m udp --dport 53 -j REDIRECT --to-ports %s"%args.dns_port)
    display("[i] Tip to avoid leaks : Block IPv6. For ipv4 put a DROP policy on OUTPUT and only allow TCP to your socks proxy. cf. the iptables.rules example file")


    try:
        server = Pr0cks5Server(bind_address, args.port)
        if args.verbose:
            server.verbose=True
        asyncore.loop()
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(traceback.format_exc())
        sys.exit(1)

