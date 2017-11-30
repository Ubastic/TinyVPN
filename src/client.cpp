#include "client.h"

#include <arpa/inet.h>
#include <assert.h>

#ifdef DEBUG
#include <iostream>
#endif

namespace vpn {

Client::Client(const std::string& addr, int port)
    : _socket(Socket::IPv4, Socket::UDP), _epoll(), _tun("192.168.10.111"),
    _srv_port(port), _srv_addr(addr) {
    assert(_epoll.add_read_event(_tun.fd()) == 0);
    assert(_epoll.add_read_event(_socket.fd()) == 0);
}

void Client::run() {
    assert(_tun.up() == 0);
    char buf[4096];
    for ( ; ; ) {
        std::vector<struct epoll_event> events(_epoll.wait());

        for (const auto& event : events) {
            if (event.data.fd == _tun.fd()) {
                int nread = _tun.read(buf, sizeof(buf));
                assert(nread != -1);
                assert(_socket.sendto(buf, nread, _srv_addr, _srv_port) == nread);
#ifdef DEBUG
                std::cout << "recvfrom: " << _tun.ip()
                    << "sendto: " << _srv_addr << ":" << _srv_port << std::endl << std::endl;
#endif
            } else if (event.data.fd == _socket.fd()) {
                struct sockaddr_in sock;
                socklen_t len = sizeof(sock);
                int nread = _socket.recvfrom(buf, sizeof(buf), (struct sockaddr*)&sock, &len);
                assert(nread != -1);
                assert(_tun.write(buf, nread) == nread);

                char buf[1230];
                inet_ntop(AF_INET, &sock.sin_addr, buf, sizeof(buf));
#ifdef DEBUG
                std::cout << "recvfrom" << buf << ":" << ntohs(sock.sin_port)
                    << "sendto: " << _tun.ip() << std::endl << std::endl;
#endif
            } else {
                /* nerver do this */
                assert(false);
            }
        }
    }
}

} /* namespace vpn */
