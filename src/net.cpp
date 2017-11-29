#include "net.h"

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

IP::IP(char *data, int size, Memory option)
    : _ip(nullptr), _option(option), _inner(nullptr), _data(nullptr), _size(size) {
    assert(data && size >= 0);
    assert(static_cast<unsigned long long>(size) >= sizeof(struct iphdr));
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

    if (_ip->protocol == IPPROTO_TCP) {
        _inner = new class TCP(_data + sizeof(struct iphdr));
    } else if (_ip->protocol == IPPROTO_UDP) {
        _inner = new class UDP(_data + sizeof(struct iphdr));
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
    inet_pton(AF_INET, addr.c_str(), &_ip->saddr);
}

Protocol IP::protocol() {
    if (_ip->protocol == IPPROTO_TCP) {
        return P_TCP;
    } else if (_ip->protocol == IPPROTO_UDP) {
        return P_UDP;
    } else {
        return P_NSY;
    }
}

/* For UDP/TCP compute checksum */
struct MockHeader {
    uint32_t    saddr;
    uint32_t    daddr;
    uint8_t     zero;
    uint8_t     protocol;
    uint16_t    tot_len;
    /* UDP/TCP origin header and data */
    char        origin[0];
};

/* Same as class MockHeaderRAII */
using MockHeaderPtr = std::shared_ptr<MockHeader>;

/* Inner function of computing checksum */
static uint16_t __checksum(const void* data, int size) {
    assert(data && size >= 8);

    uint32_t checksum = 0;
    const uint16_t *word = reinterpret_cast<const uint16_t*>(data);

    while (size > 1) {
        checksum += *word++;
        size -= 2;
    }

    if (size) {
        checksum += *reinterpret_cast<const uint8_t*>(word);
    }

    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum & 0xffff) + (checksum >> 16);

    return static_cast<uint16_t>(~checksum);
};

void TCP::calc_checksum(const struct iphdr *ip) {
    int tot_len = sizeof(MockHeader) + ip->tot_len - sizeof(struct iphdr);
    MockHeaderPtr tcp_header(reinterpret_cast<MockHeader*>(malloc(tot_len)));
    tcp_header->saddr = ip->saddr;
    tcp_header->daddr = ip->daddr;
    tcp_header->zero = 0;
    tcp_header->protocol = IPPROTO_TCP;
    tcp_header->tot_len = htons(tot_len);

    _tcp->check = __checksum(tcp_header.get(), tot_len);
}

void UDP::calc_checksum(const struct iphdr *ip) {
    int tot_len = sizeof(MockHeader) + ip->tot_len - sizeof(struct iphdr);
    MockHeaderPtr udp_header(reinterpret_cast<MockHeader*>(malloc(tot_len)));
    udp_header->saddr = ip->saddr;
    udp_header->daddr = ip->daddr;
    udp_header->zero = 0;
    udp_header->protocol = IPPROTO_UDP;
    udp_header->tot_len = htons(tot_len);

    _udp->check = __checksum(udp_header.get(), tot_len);
}

void IP::calc_checksum() {
    _ip->check = 0;
    _ip->check = htons(__checksum(_ip, sizeof(struct iphdr)));
}

const char* IP::raw_data() {
    if (_inner) {
        if (protocol() == P_TCP || protocol() == P_UDP) {
            /* Safe down cast */
            TransLayer *real_type = dynamic_cast<TransLayer*>(_inner);
            real_type->calc_checksum(_ip);
        } else {
            return nullptr;
        }
    }
    calc_checksum();
    return _data;
}

} /* namespace vpn */
