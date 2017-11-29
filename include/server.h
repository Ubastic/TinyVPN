#ifndef VPN_SERVER_H
#define VPN_SERVER_H

#include <string>
#include <memory>
#include <map>

#include "common.h"

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

    std::map<AddrPort, AddrPort>  _snat_map;
    std::map<AddrPort, AddrPort>  _sock_map;
    std::vector<bool> _port_pool;
};

} /* namespace vpn */

#endif
