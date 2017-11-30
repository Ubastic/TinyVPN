#include "vpn_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>

#ifdef DEBUG
#include <iostream>
#endif
#include <vector>

namespace vpn {

static const int MAX_EVENTS = 512;

Server::Server(const std::string& addr, int port)
    : _socket(Socket::IPv4, Socket::UDP), _epoll(), _tun(addr), _port(port) {
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
                /* Path:
                 *      Server -> Trans -> Client
                 * */
                server2client();
            } else if (event.data.fd == _socket.fd()) {
                /* Path:
                 *      Client -> Trans -> Server
                 * */
                client2server();
            } else {
                /* nerver do this */
                assert(false);
            }
        }
    }
}

void Server::client2server() {
    char buf[4096];

    struct sockaddr sock;
    socklen_t len = sizeof(sock);
    int nread = _socket.recvfrom(buf, sizeof(buf), &sock, &len);
    assert(nread != -1);
  
    std::shared_ptr<IP> ip = get_ip_packet(buf, nread);
    if (ip->protocol() == P_TCP || ip->protocol() == P_UDP) {
        ip->set_saddr(_tun.ip());

        /* Safe down cast */
        TransLayer *trans = dynamic_cast<TransLayer*>(ip->inner());
        assert(trans != nullptr);

        ip->set_saddr(_tun.ip());
        trans->set_sport(_nat.snat(ip->saddr(), trans->sport(), sock));

        _tun.write(ip->raw_data(), ip->size());
    } else {
        return ;
    }

#ifdef DEBUG
    std::cout << "from client to server" << std::endl;
#endif
}

void Server::server2client() {
    char buf[4096];

    int nread = _tun.read(buf, sizeof(buf));
    assert(nread != -1);
  
    std::shared_ptr<IP> ip = get_ip_packet(buf, nread);
    if (ip->protocol() == P_TCP || ip->protocol() == P_UDP) {
        /* Safe down cast */
        TransLayer *trans = dynamic_cast<TransLayer*>(ip->inner());
        std::shared_ptr<OriginData> origin = _nat.dnat(trans->dport()); 

        ip->set_daddr(origin->addr);
        trans->set_dport(origin->port);
        
        _socket.sendto(buf, nread, &(origin->sock), sizeof(origin->sock));
    }

#ifdef DEBUG
    std::cout << "from server to client" << std::endl;
#endif
}

std::shared_ptr<IP> Server::get_ip_packet(char *buf, int size) {
    if (static_cast<size_t>(size) < sizeof(struct iphdr)) {
        return nullptr;
    }

    std::shared_ptr<IP> ip(new IP(buf, size, IP::ALLOC));

    if (ip->protocol() != P_TCP
            && ip->protocol() != P_UDP) {
        return nullptr;
    }

    if (ip->inner() == nullptr) {
        return nullptr;
    }

    return ip;
}

} /* namespace vpn */
