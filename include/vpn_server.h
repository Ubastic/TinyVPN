#ifndef VPN_SERVER_H
#define VPN_SERVER_H

#include <string>
#include <memory>
#include <map>

#include "vpn_common.h"
#include "vpn_nat.h"
#include "vpn_net.h"

namespace vpn {

using AddrPort = std::pair<std::string, int>;

class Server {
public:
    Server(const std::string& addr, int port);
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    void run();
private:
    Socket  _socket;
    Epoll   _epoll;
    Tun     _tun;
    int     _port;

    NAT     _nat;

    void client2server();
    void server2client();

    std::shared_ptr<IP> get_ip_packet(char *buf, int size);
};

} /* namespace vpn */

#endif
