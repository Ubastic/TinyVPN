#include "server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>

#ifdef DEBUG
#include <iostream>
#endif
#include <vector>

#include "net.h"

namespace vpn {

static const int MAX_EVENTS = 512;
static const int MAX_PORT = 65536;

Server::Server(const std::string& addr, int port)
    : _socket(Socket::IPv4, Socket::UDP), _epoll(), _tun(addr), _port(port),
    _snat_map(), _port_pool(MAX_PORT, false) {
    _epoll.add_read_event(_socket.fd());
    _epoll.add_read_event(_tun.fd());
}

void Server::run() {
    assert(_tun.up() == 0);
    assert(_socket.bind(_port) == 0);

    char buf[4096];
    for ( ; ; ) {
        std::vector<struct epoll_event> events(_epoll.wait());

        for (const auto& event : events) {
            if (event.data.fd == _tun.fd()) {
                int nread = _tun.read(buf, sizeof(buf));
                assert(nread != -1);

                if (nread < sizeof(struct iphdr)) {
                    continue;
                }
                IP ip(buf, nread, IP::ALLOC);
                if (ip.protocol() == P_TCP || ip.protocol() == P_UDP) {
                    TransLayer *real_type = dynamic_cast<TransLayer*>(ip.inner());
                    int port = real_type->dport();

                    /* pair<addr. port> */
                    AddrPort origin = _snat_map[{_tun.ip(), port}];
                    ip.set_daddr(origin.first);
                    assert(_sock_map.find(origin) != _sock_map.end());
                    AddrPort sock_origin = _sock_map[origin];
                    assert(_socket.sendto(ip.raw_data(), ip.size(), sock_origin.first, sock_origin.second) == nread);
#ifdef DEBUG
                    std::cout << "recvfrom: " << _tun.ip()
                        << " sendto: " << sock_origin.first << ":" << sock_origin.second << std::endl;
#endif
                }
            } else if (event.data.fd == _socket.fd()) {
                struct sockaddr_in sock;
                socklen_t len = sizeof(sock);
                int nread = _socket.recvfrom(buf, sizeof(buf),
                        reinterpret_cast<struct sockaddr*>(&sock), &len);
                assert(nread != -1);
                char sock_addr[32];
                inet_ntop(AF_INET, &sock.sin_addr, sock_addr, sizeof(sock_addr));

                if (nread < sizeof(struct iphdr)) {
                    continue;
                }
                IP ip(buf, nread, IP::ALLOC);

                std::string src_addr = ip.saddr();
                if (ip.protocol() == P_TCP || ip.protocol() == P_UDP) {
                    TransLayer *real_type = dynamic_cast<TransLayer*>(ip.inner());
                    int port = real_type->sport();
                    _snat_map[{_tun.ip(), port}] = {src_addr, port};
                    _sock_map[{src_addr, port}] = {sock_addr, ntohs(sock.sin_port)};
                    ip.set_saddr(_tun.ip());
                    _tun.write(ip.raw_data(), ip.size());
#ifdef DEBUG
                    std::cout << "recvfrom: " << sock_addr << ":" << ntohs(sock.sin_port)
                        << " sendto: " << _tun.ip()<< std::endl;
#endif
                }
            } else {
                /* nerver do this */
                assert(false);
            }
        }
    }
}

} /* namespace vpn */
