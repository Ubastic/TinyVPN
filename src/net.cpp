#include "net.h"

#include <arpa/inet.h>
#include <assert.h>
#include <string.h>

/* The FALLTHROUGH_INTENDED macro can be used to annotate implicit fall-through
 * between switch labels. The real definition should be provided externally.
 * This one is a fallback version for unsupported compilers. */
#ifndef FALLTHROUGH_INTENDED
#define FALLTHROUGH_INTENDED do {  } while(0)
#endif

namespace vpn {

Protocol::Protocol(char* data, int size, Option opt)
    : _inner(nullptr), _data(nullptr),
      _size(size), _option(opt) {
    switch (opt) {
        case REUSE:
            _data = data;
            break;
        case ALLOC:
            _data = new char[size];
            memcpy(_data, data, size);
            break;
        default:
            assert(0);
    }
}

Protocol::~Protocol() {
    switch(_option) {
        case ALLOC:
            delete _data;
            FALLTHROUGH_INTENDED;
        default:
            break;
    }
}

Protocol* Protocol::find(Type p) {
    while (_inner && _inner->get_type() != p) {
        _inner = _inner->_inner;
    }
    return _inner.get();
}

const char* Protocol::raw_data() {
    if (_inner) {
        _inner->calc_checksum();
    }
    calc_checksum();
    return _data;
}

/* Inner function of computing checksum */
static uint16_t __checksum(const void* data, int size) {
    assert(data && size >= 8);

    uint16_t checksum = 0;
    const uint16_t *word = reinterpret_cast<const uint16_t*>(data);

    int nleft = size;
    while (nleft > 1) {
        checksum += *word;
        word += 2;
        nleft -= 2;
    }

    if (nleft) {
        checksum += *reinterpret_cast<const uint8_t*>(word);
    }

    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum & 0xffff) + (checksum >> 16);

    return ~checksum;
}

TCP::TCP(char* data, int size, Option opt)
    : Protocol(data, size, opt), _tcp(nullptr) {
    assert(size >= static_cast<int>(sizeof(struct tcphdr)));
    _tcp = reinterpret_cast<struct tcphdr*>(Protocol::data());
}

void TCP::calc_checksum() {

}

UDP::UDP(char* data, int size, Option opt)
    : Protocol(data, size, opt), _udp(nullptr) {
    assert(size >= static_cast<int>(sizeof(struct udphdr)));
    _udp = reinterpret_cast<struct udphdr*>(Protocol::data());
}

void UDP::calc_checksum() {

}

IP::IP(char* data, int size, Option opt)
    : Protocol(data, size, opt), _ip(nullptr) {
    assert(size >= static_cast<int>(sizeof(struct iphdr)));
    _ip = reinterpret_cast<struct iphdr*>(Protocol::data());

    char* ptr = Protocol::data() + _ip->ihl * 4;
    Protocol *inner = nullptr;
    if (_ip->protocol == IPPROTO_TCP) {
        inner = new class TCP(ptr, _ip->tot_len - _ip->ihl * 4, REUSE);
    } else if (_ip->protocol == IPPROTO_UDP) {
        inner = new class UDP(ptr, _ip->tot_len - _ip->ihl * 4, REUSE);
    }

    Protocol::set_inner(inner);
}

void IP::calc_checksum() {
    _ip->check = 0;
    _ip->check = htons(__checksum(_ip, _ip->ihl * 5));
}

std::string IP::saddr() {
    char buf[32];
    inet_ntop(AF_INET, &_ip->saddr, buf, sizeof(buf));
    return buf;
}

std::string IP::daddr() {
    char buf[32];
    inet_ntop(AF_INET, &_ip->saddr, buf, sizeof(buf));
    return buf;
}

void IP::set_saddr(const std::string &addr) {
    inet_pton(AF_INET, addr.c_str(), &_ip->saddr);
}

void IP::set_daddr(const std::string &addr) {
    inet_pton(AF_INET, addr.c_str(), &_ip->daddr);
}

} /* namespace vpn */

