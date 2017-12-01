#include "vpn_net.h"

#include <netinet/in.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* The FALLTHROUGH_INTENDED macro can be used to annotate implicit fall-through
 * between switch labels. The real definition should be provided externally.
 * This one is a fallback version for unsupported compilers. */
#ifndef FALLTHROUGH_INTENDED
#define FALLTHROUGH_INTENDED do {  } while(0)
#endif

namespace vpn {

TCP::TCP(char *data) : _tcp(reinterpret_cast<struct tcphdr*>(data)) {  }
UDP::UDP(char *data) : _udp(reinterpret_cast<struct udphdr*>(data)) {  }
ICMP::ICMP(char *data) : _icmp(reinterpret_cast<struct icmphdr*>(data)) {  }

IP::IP(char *data, int size, Memory option)
    : _ip(nullptr), _option(option), _inner(nullptr), _data(nullptr), _size(size) {
    init(data, size, option);
}

void IP::init(char *data, int size, Memory option) {
    switch (option) {
        case REUSE:
            _data = data;
            break;
        case ALLOC:
            _data = reinterpret_cast<char*>(malloc(size));
            memcpy(_data, data, size);
            break;
        default:
            assert(false);
    }

    _ip = reinterpret_cast<struct iphdr*>(_data);

    if (protocol() == P_TCP) {
        _inner = new TCP(_data + sizeof(struct iphdr));
    } else if (protocol() == P_UDP) {
        _inner = new UDP(_data + sizeof(struct iphdr));
    } else if (protocol() == P_ICMP) {
        _inner = new ICMP(_data + sizeof(struct iphdr));
    }
}

IP::~IP() {
    switch (_option) {
        case ALLOC:
            free(_data);
            FALLTHROUGH_INTENDED;
        default:
            if (_inner) {
                delete _inner;
            }
            break;
    }
}

std::string IP::saddr() {
    char buf[32];
    inet_ntop(AF_INET, &_ip->saddr, buf, sizeof(buf));
    return buf;
}

std::string IP::daddr() {
    char buf[32];
    inet_ntop(AF_INET, &_ip->daddr, buf, sizeof(buf));
    return buf;
}

void IP::set_saddr(const std::string& addr) {
    inet_pton(AF_INET, addr.c_str(), &_ip->saddr);
}

void IP::set_daddr(const std::string& addr) {
    inet_pton(AF_INET, addr.c_str(), &_ip->daddr);
}

Protocol IP::protocol() {
    if (_ip->protocol == IPPROTO_TCP) {
        return P_TCP;
    } else if (_ip->protocol == IPPROTO_UDP) {
        return P_UDP;
    } else if (_ip->protocol == IPPROTO_ICMP) {
        return P_ICMP;
    }
    return P_NSY;
}

/* For UDP/TCP compute checksum */
struct PseudoHeader {
    uint32_t    saddr;
    uint32_t    daddr;
    uint8_t     zero;
    uint8_t     protocol;
    uint16_t    tot_len;
    /* UDP/TCP origin header and data */
    char        origin[0];
};

/* Same as class PseudoHeaderRAII */
using PseudoHeaderPtr = std::shared_ptr<PseudoHeader>;

/* Inner function of computing checksum */
static uint16_t __checksum(const void* data, int size) {
    assert(data && size >= 8);

    uint32_t checksum = 0;
    const uint16_t *word = reinterpret_cast<const uint16_t*>(data);

    while (size > 1) {
        checksum += *word++;
        if (checksum > 0xffff) {
            checksum = (checksum & 0xffff) + (checksum >> 16);
        }
        size -= 2;
    }

    if (size) {
        checksum += *reinterpret_cast<const uint8_t*>(word);
    }

    return static_cast<uint16_t>(~checksum);
};

void TCP::calc_checksum(const struct iphdr *ip) {
    _tcp->check = 0;

    /*
     * ----------------------------------------
     * | PseudoHeader | TCP Header | TCP Data |
     * ----------------------------------------
     * */
    int tot_len = sizeof(PseudoHeader) + ntohs(ip->tot_len) - sizeof(struct iphdr);
    PseudoHeaderPtr tcp_header(reinterpret_cast<PseudoHeader*>(malloc(tot_len)));
    tcp_header->saddr = ip->saddr;
    tcp_header->daddr = ip->daddr;
    tcp_header->zero = 0;
    tcp_header->protocol = IPPROTO_TCP;
    tcp_header->tot_len = htons(tot_len - sizeof(PseudoHeader));
    memcpy(tcp_header->origin, _tcp, tot_len - sizeof(PseudoHeader));

    _tcp->check = __checksum(tcp_header.get(), tot_len);
}

void UDP::calc_checksum(const struct iphdr *ip) {
    _udp->check = 0;

    /*
     * ----------------------------------------
     * | PseudoHeader | UDP Header | UDP Data |
     * ----------------------------------------
     * */
    int tot_len = sizeof(PseudoHeader) + ntohs(ip->tot_len) - sizeof(struct iphdr);
    PseudoHeaderPtr udp_header(reinterpret_cast<PseudoHeader*>(malloc(tot_len)));
    udp_header->saddr = ip->saddr;
    udp_header->daddr = ip->daddr;
    udp_header->zero = 0;
    udp_header->protocol = IPPROTO_TCP;
    udp_header->tot_len = htons(tot_len - sizeof(PseudoHeader));
    memcpy(udp_header->origin, _udp, tot_len - sizeof(PseudoHeader));

    _udp->check = __checksum(udp_header.get(), tot_len);
}

void ICMP::calc_checksum(const struct iphdr *ip) {
    _icmp->checksum = 0;
    _icmp->checksum = __checksum(_icmp, ntohs(ip->tot_len) - sizeof(struct iphdr));
}

void IP::calc_checksum() {
    _ip->check = 0;
    _ip->check = __checksum(_ip, sizeof(struct iphdr));
}

const char* IP::raw_data() {
    if (_inner) {
        _inner->calc_checksum(_ip);
    }
    calc_checksum();
    return _data;
}

} /* namespace vpn */
