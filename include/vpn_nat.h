#ifndef VPN_NAT_H
#define VPN_NAT_H

#include <netinet/in.h>

#include <unordered_map>
#include <string>
#include <memory>

namespace vpn {

struct NATNode {
    struct sockaddr_in sock;
    std::string  addr;
    time_t       use;
    int          port;
    int          new_port;

    NATNode     *prev;
    NATNode     *next;

    NATNode(int p) : new_port(p), prev(nullptr), next(nullptr) {  }
};

struct OriginData {
    struct sockaddr_in sock;
    std::string addr;
    int port;
};

class NAT {
public:
    explicit NAT();
    ~NAT();
    NAT(const NAT&) = delete;
    NAT& operator=(const NAT&) = delete;

    /* Return a new port */
    int snat(const std::string& addr, int port, struct sockaddr_in sock);
    /* Return the OriginData
     * Port is returned by a previous snat()
     * */
    std::shared_ptr<OriginData> dnat(int port);

    /* Available to ICMP */
    void snat(const std::string& saddr, const std::string& daddr, struct sockaddr_in sock);
    std::shared_ptr<OriginData> dnat(const std::string& daddr);
private:
    /* Dummy head of list */
    NATNode  _nat;
    NATNode  _in_use;

    /* Available to ICMP */
    using AddrMap = std::unordered_map<std::string, OriginData>;
    AddrMap  _addrmap;

    void init();

    /* TODO: Using skiplist to optimize */
    NATNode* lookup(int port);
    NATNode* lookup(const std::string& addr, int port);

    void remove(NATNode *node);
    void append(NATNode *list, NATNode *node);

    /* Prune _in_use when _nat is empty */
    void prune(int timeout);

    bool empty(const NATNode *list);
};

} /* namespace vpn */

#endif
