//go:build ignore

#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <stdbool.h>

#define IPv4LEN 4
#define IPv6LEN 16

#define IPV4_SUBNET 0x00001E0A // 10.30.0.0 in big endian
#define IPV4_MASK 0x0000FFFF // 255.255.255.0 in big endian

#define IPV6_SUBNET { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define IPV6_MASK { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }

extern bool is_ipv4_in_network(__be32 addr) {
    return (addr & IPV4_MASK) == (IPV4_SUBNET & IPV4_MASK);
}

extern bool is_ipv6_in_network(struct in6_addr *addr) {
    unsigned char subnet[16] = IPV6_SUBNET;
    unsigned char mask[16] = IPV6_MASK;

    for (int i = 0; i < 16; i++) {
        if ((addr->in6_u.u6_addr8[i] & mask[i]) != (subnet[i] & mask[i])) {
            return false;
        }
    }
    return true;
}
