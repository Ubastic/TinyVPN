#ifndef VPN_NET_H
#define VPN_NET_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>

#include <string>
#include <memory>

namespace vpn {

class Protocol {
public:
    /* Reuse or alloc memory. */
    enum Option {
        REUSE = 0,
        ALLOC = 1
    };
    Protocol(char* data, int size, Option opt);
    Protocol(const Protocol&) = delete;
    Protocol& operator=(const Protocol&) = delete;
    virtual ~Protocol();

    /* Find inner protocol. */
    enum Type {
        TCP = 0,
        UDP,
        IP
    };
    Protocol* find(Type p);

    /* Checksum will be computed iff raw_data() is called. */
    virtual int checksum() = 0;
    virtual void calc_checksum() = 0;

    const char* raw_data();
    virtual Type get_type() = 0;
protected:
    /* TODO: How to do better? */
    int size()  { return _size; }
    char* data() { return _data; }
    void set_inner(Protocol *p) { _inner.reset(p); }
private:
    std::shared_ptr<Protocol>  _inner;
    char      *_data;
    int        _size;
    Option     _option;
};

class TCP : public Protocol {
public:
    TCP(char* data, int size, Option opt);
    ~TCP() {  }
    void calc_checksum();
    int checksum() { return ntohs(_tcp->check); }
    Type get_type() { return Type::TCP; }

    int sport() { return ntohs(_tcp->source); }
    int dport() { return ntohs(_tcp->dest); }
    void set_sport(int port) { _tcp->source = htons(port); }
    void set_dport(int port) { _tcp->dest = htons(port); }
private:
    struct tcphdr* _tcp;
};

class UDP : public Protocol {
public:
    UDP(char* data, int size, Option opt);
    ~UDP() {  }
    void calc_checksum();
    int checksum() { return ntohs(_udp->check); }
    Type get_type() { return Type::UDP; }

    int sport() { return ntohs(_udp->source); }
    int dport() { return ntohs(_udp->dest); }
    void set_sport(int port) { _udp->source = htons(port); }
    void set_dport(int port) { _udp->dest = htons(port); }
private:
    struct udphdr* _udp;
};

class IP : public Protocol {
public:
    IP(char* data, int size, Option opt);
    ~IP() {  }
    void calc_checksum();
    int checksum() { return ntohs(_ip->check); }
    Type get_type() { return Type::IP; }

    int version() { return ntohs(_ip->version); }
    int protocol() { return ntohs(_ip->protocol); }
    std::string saddr();
    std::string daddr();
    void set_saddr(const std::string &addr);
    void set_daddr(const std::string &addr);
private:
    struct iphdr* _ip;
};

} /* namespace vpn */

#endif
