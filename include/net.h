#ifndef VPN_NET_H
#define VPN_NET_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>

#include <string>
#include <memory>

namespace vpn {

enum Protocol {
    P_ICMP = 0,
    P_TCP,
    P_UDP,
    P_IP,
    P_NSY  // Not support yet 
};

class Inner {
public:
    Inner() = default;
    virtual ~Inner() {  }
};

class TransLayer : public Inner {
public:
    TransLayer() = default;
    virtual ~TransLayer() {  }
    TransLayer& operator=(const TransLayer&) = delete;
    TransLayer(const TransLayer&) = delete;

    virtual int sport() = 0;
    virtual int dport() = 0;
    virtual int set_sport(int port) = 0;
    virtual int set_dport(int port) = 0;

    virtual int checksum() = 0;
    virtual void calc_checksum(const struct iphdr *ip) = 0;
};

class TCP : public TransLayer {
public:
    /* Reuse memory(char *data) */
    explicit TCP(char *data);
    ~TCP() = default;
    TCP& operator=(const TCP&) = delete;
    TCP(const TCP&) = delete;

    int sport() { return ntohs(_tcp->source); }
    int dport() { return ntohs(_tcp->dest); }
    int set_sport(int port) { return _tcp->source = htons(port); }
    int set_dport(int port) { return _tcp->dest = htons(port); }

    int checksum() { return ntohs(_tcp->check); }
    void calc_checksum(const struct iphdr *ip);
private:
    struct tcphdr *_tcp;
};

class UDP : public TransLayer {
public:
    /* Reuse memory(char *data) */
    explicit UDP(char *data);
    ~UDP() = default;
    UDP& operator=(const UDP&) = delete;
    UDP(const UDP&) = delete;

    int sport() { return ntohs(_udp->source); }
    int dport() { return ntohs(_udp->dest); }
    int set_sport(int port) { return _udp->source = htons(port); }
    int set_dport(int port) { return _udp->dest = htons(port); }

    int checksum() { return ntohs(_udp->check); }
    void calc_checksum(const struct iphdr *ip);
private:
    struct udphdr *_udp;
};

// TODO
class ICMP : public Inner {
public:
private:
};

class IP {
public:
    /* Reuse or alloc memory */
    enum Memory {
        REUSE = 0,
        ALLOC = 1
    };
    explicit IP(char *data, int size, Memory option);
    ~IP();
    IP& operator=(const IP&) = delete;
    IP(const IP&) = delete;

    std::string saddr();
    std::string daddr();
    void set_saddr(const std::string& addr);
    void set_daddr(const std::string& addr);

    Protocol protocol();

    int checksum() { return ntohs(_ip->check); }
    void calc_checksum();

    const char* raw_data();
private:
    Memory   _option;
    Inner   *_inner;
    char    *_data;
    struct iphdr  *_ip;

    void init(char *data, int isze, Memory option);
};

} /* namespace vpn */

#endif
