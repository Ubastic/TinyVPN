#ifndef VPN_NAT_H
#define VPN_NAT_H

#include <netinet/in.h>

#include <string>
#include <memory>

namespace vpn {

struct NATNode {
    struct sockaddr sock;
    std::string  addr;
    time_t       use;
    int          port;
    int          new_port;

    NATNode     *prev;
    NATNode     *next;

    NATNode(int p) : new_port(p), prev(nullptr), next(nullptr) {  }
};

struct OriginData {
    struct sockaddr sock;
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
    int snat(const std::string& addr, int port, struct sockaddr sock);
    /* Return the OriginData
     * Port is returned by a previous snat()
     * */
    std::shared_ptr<OriginData> dnat(int port);
private:
    /* Dummy head of list */
    NATNode  _nat;
    NATNode  _in_use;

    void init();

    NATNode* lookup(int port);
    NATNode* lookup(const std::string& addr, int port);

    void remove(NATNode *node);
    void append(NATNode *list, NATNode *node);
    
    /* Prune _in_use when _nat is empty */
    void prune();

    bool empty(const NATNode *list);
};

} /* namespace vpn */

#endif
