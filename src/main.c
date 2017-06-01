#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <asm/types.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

/* Custom error */
#define NO_ERROR 0
#define INVALID_INTERFACE -1
#define INVALID_SUBNET -2
#define INVALID_IP -3
#define SOCKET_ERROR -4
#define INVALID_INTERFACE_NAME -5
#define AF_INET_ERROR -6
#define NOT_ARP_PACKET -7
#define NOT_ARP_REPLY -8

#define ERROR(error) \
    switch (error) { \
        case (NO_ERROR): \
            break; \
        case (INVALID_INTERFACE): { \
            fprintf(stderr, "Invalid interface\n"); \
            exit(EXIT_FAILURE); \
        } \
        case (INVALID_SUBNET): { \
            fprintf(stderr, "Invalid subnet\n"); \
            exit(EXIT_FAILURE); \
        } \
        case (INVALID_IP): { \
            fprintf(stderr, "Invalid ip in ARP request\n"); \
            exit(EXIT_FAILURE); \
        } \
        case (SOCKET_ERROR): { \
            fprintf(stderr, "Socket error\n"); \
            exit(EXIT_FAILURE); \
        } \
        case (INVALID_INTERFACE_NAME): { \
            fprintf(stderr, "Too long interface name\n"); \
            exit(EXIT_FAILURE); \
        } \
        case (AF_INET_ERROR): { \
            fprintf(stderr, "Socket not AF_INET"); \
            exit(EXIT_FAILURE); \
        } \
        case (NOT_ARP_PACKET): { \
            fprintf(stderr, "Not an ARP packet"); \
        } \
        case (NOT_ARP_REPLY): { \
            fprintf(stderr, "Not an ARP reply"); \
        } \
        default: { \
            perror(""); \
            exit(EXIT_FAILURE); \
        } \
    }

/* IPv4 subnet */
struct subnet {
    uint32_t start;
    uint32_t end;
    uint32_t mask;
};

/* ARP header */
struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

unsigned active_host = 0;

/* 
 * Print a simple "how to use".
 */
void print_usage(const char *arg) {
    fprintf(stderr, "Usage: %s -i <INTERFACE_NAME> -s <SUBNET> -t <TIMEOUT>\n", arg);
}

/* 
 * Verify if network interface exists.
 */
int check_existent_interface(char *interface) {
    struct ifaddrs *ifa, *if_aux;

    /* Get list of all network interfaces */
    if (getifaddrs(&ifa) == -1)
        return errno;

    /* Search interface in list */
    if_aux = ifa;
    for (; if_aux != NULL; if_aux = if_aux->ifa_next) {
        if (if_aux->ifa_addr == NULL)
            continue;
        if (strcmp(if_aux->ifa_name, interface) == 0) {
            freeifaddrs(ifa);
            return NO_ERROR;
        }
    }

    freeifaddrs(ifa);
    return INVALID_INTERFACE;
}

/* 
 * Split "address/subnet" in "address'\0'subnet".
 */
char *sub_split(char *string, char delim) {
    uint8_t i = 0;

    while (string[i] != '\0') {
        if (string[i] == delim) {
            string[i] = '\0';
            return &(string[i+1]);
        }
        i++;
    }
    return NULL;
}

/* 
 * Cast a string that represents IPv4 address to uint32_t.
 */
uint32_t cast_IPv4_to_uint(char *ipAddress) {
    uint32_t ipbytes[4];
    sscanf(ipAddress, "%u.%u.%u.%u", &ipbytes[3], &ipbytes[2], &ipbytes[1], &ipbytes[0]);
    return ipbytes[0] | ipbytes[1] << 8 | ipbytes[2] << 16 | ipbytes[3] << 24;
}

/* 
 * Cast an uint32_t that represents IPv4 address to string.
 */
char * cast_uint_to_IPv4(uint32_t ip) {
    char *_ip = (char *) calloc(15, sizeof(char));
    unsigned char ipbytes[4];

    ipbytes[0] = ip & 0xFF;
    ipbytes[1] = (ip >> 8) & 0xFF;
    ipbytes[2] = (ip >> 16) & 0xFF;
    ipbytes[3] = (ip >> 24) & 0xFF;   

    sprintf(_ip, "%d.%d.%d.%d", ipbytes[3], ipbytes[2], ipbytes[1], ipbytes[0]);
    return _ip;   
}

/* 
 * Invert an uint32_t that represents IPv4 address to an inverted IPv4 represented by uint32_t.
 */
uint32_t invert_IP(uint32_t ip) {
    char * _ip = cast_uint_to_IPv4(ip);
    uint32_t ipbytes[4];
    sscanf(_ip, "%u.%u.%u.%u", &ipbytes[3], &ipbytes[2], &ipbytes[1], &ipbytes[0]);
    free(_ip);
    return ipbytes[0] << 24 | ipbytes[1] << 16 | ipbytes[2] << 8 | ipbytes[3] << 0;
}

/* 
 * Get subnet mask from prefix.
 */
uint32_t get_mask(uint8_t prefix) {
    uint32_t mask = (1 << (32 - prefix)) - 1;
    return ~mask;
}

/* 
 * Get begin and end of a subnet.
 */
struct subnet *parse_subnet(char *address) {
    struct subnet *snet = (struct subnet *) calloc(1, sizeof(struct subnet));
    char *prefix = sub_split(address, '/');

    if (prefix == NULL)
        snet->mask = get_mask(atoi("32"));
    else {
        uint8_t pref = atoi(prefix);

        if (pref > 32 || pref == 0) {
            free(snet);
            errno = EINVAL;
            return NULL;
        }
        snet->mask = get_mask(pref);
    }

    uint32_t uint_IP = cast_IPv4_to_uint(address);
    snet->start = uint_IP & snet->mask;
    snet->end = uint_IP | ~snet->mask;

    return snet;
}

/*
 * Converts struct sockaddr with an IPv4 address to network byte order uin32_t.
 * Returns 0 on success.
 */
int int_ip4(struct sockaddr *addr, uint32_t *ip) {
    if (addr->sa_family == AF_INET) {
        /* Structure describing an Internet (IP) socket address. */
        struct sockaddr_in *ip_sock = (struct sockaddr_in *) addr;
        /* Internet address */
        *ip = ip_sock->sin_addr.s_addr;
        return NO_ERROR;
    } else 
        return AF_INET_ERROR;
}

/*
 * Writes interface IPv4 address as network byte order to ip.
 * Returns 0 on success.
 */
int get_if_ip4(int fd, const char *ifname, uint32_t *ip) {
    /* Interface request structure used for socket ioctl's */
    struct ifreq ifrs;
    memset(&ifrs, 0, sizeof(struct ifreq));

    /* Max length of interface name */
    if (strlen(ifname) > (IFNAMSIZ - 1))
        return INVALID_INTERFACE_NAME;

    strcpy(ifrs.ifr_name, ifname);
    /* The ioctl() function manipulates the underlying device parameters of special files */
    if (ioctl(fd, SIOCGIFADDR, &ifrs) == -1)
        return errno;

    return int_ip4(&ifrs.ifr_addr, ip);
}

/*
 * Print some information about sent or received packet.
 */
void print_arp_packet(struct arp_header *arp_resp) {
    unsigned short _opc = ntohs(arp_resp->opcode);

    if (_opc == 1)
        printf("ARP REQUEST:\n");
    else if (_opc == 2)
        printf("ARP RESPONSE:\n");

    printf("\tSender IP: %u.%u.%u.%u\n", 
        arp_resp->sender_ip[0],
        arp_resp->sender_ip[1],
        arp_resp->sender_ip[2],
        arp_resp->sender_ip[3]);

    printf("\tSender MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
          arp_resp->sender_mac[0],
          arp_resp->sender_mac[1],
          arp_resp->sender_mac[2],
          arp_resp->sender_mac[3],
          arp_resp->sender_mac[4],
          arp_resp->sender_mac[5]);

    printf("\tTarget IP: %u.%u.%u.%u\n", 
        arp_resp->target_ip[0],
        arp_resp->target_ip[1],
        arp_resp->target_ip[2],
        arp_resp->target_ip[3]);

    printf("\tTarget MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
          arp_resp->target_mac[0],
          arp_resp->target_mac[1],
          arp_resp->target_mac[2],
          arp_resp->target_mac[3],
          arp_resp->target_mac[4],
          arp_resp->target_mac[5]);

    if (_opc == 1)
        printf("-------------------------------\n");

    /*printf("Hardware Type: %u\n", arp_resp->hardware_type);
    printf("Hardware Length: %d\n", arp_resp->hardware_len);
    printf("Protocol Type: %u\n", arp_resp->protocol_type);
    printf("Protocol Length: %d\n", arp_resp->protocol_len);
    printf("Protocol Type: %u\n", arp_resp->opcode);*/
}

/*
 * Sends an ARP who-has request to dst_ip
 * on interface ifindex, using source mac src_mac and source ip src_ip.
 */
int send_arp_request(int fd, int ifindex, char *src_mac, uint32_t src_ip, uint32_t dst_ip) {
    unsigned char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    /* This is an Ethernet frame header. */
    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_header *arp_req = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    ssize_t ret;

    /* Broadcast */
    memset(send_req->h_dest, 0xff, MAC_LENGTH);

    /* Target MAC zero */
    memset(arp_req->target_mac, 0x00, MAC_LENGTH);

    //Set source mac to our MAC address
    memcpy(send_req->h_source, src_mac, MAC_LENGTH);
    memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);
    memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

    /* Setting protocol of the packet */
    send_req->h_proto = htons(ETH_P_ARP);

    /* Creating ARP request */
    arp_req->hardware_type = htons(HW_TYPE);
    arp_req->protocol_type = htons(ETH_P_IP);
    arp_req->hardware_len = MAC_LENGTH;
    arp_req->protocol_len = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);

    memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    /* Send a message on a socket */
    ret = sendto(fd, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
    if (ret == -1)
        return errno;

    print_arp_packet(arp_req);
    return NO_ERROR;
}

/*
 * Gets interface information by name:
 * IPv4
 * MAC
 * ifindex
 */
int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex) {
    //Interface request structure used for socket ioctl's
    struct ifreq ifr;

    /* AF_PACKET is low level packet interface.
        SOCKET_RAW provides raw network protocol access.
        The htons() function convert values between host and network byte order.*/
    int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    if (raw_socket < 0) 
        return errno;

    //Max length of interface name
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        close(raw_socket);
        return INVALID_INTERFACE_NAME;
    }

    strcpy(ifr.ifr_name, ifname);

    //Get interface index using name
    if (ioctl(raw_socket, SIOCGIFINDEX, &ifr) == -1) {
        close(raw_socket);
        return errno;
    }
    *ifindex = ifr.ifr_ifindex;
    //printf("interface index is %d\n", *ifindex);

    //Get MAC address of the interface
    if (ioctl(raw_socket, SIOCGIFHWADDR, &ifr) == -1) {
        close(raw_socket);
        return errno;
    }

    //Copy mac address to output
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    int err = get_if_ip4(raw_socket, ifname, ip);
    if (err)
        close(raw_socket);

    return err;
}

/*
 * Creates a raw socket that listens for ARP traffic on specific ifindex.
 * Writes out the socket's FD.
 * Return 0 on success.
 */
int bind_arp(int ifindex, int *fd) {
    // Submit request for a raw socket descriptor.
    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    if (*fd < 0)
        return errno;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;

    // bind a name to a socket
    if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        close(*fd);
        return errno;
    }
   
    return NO_ERROR;
}

/*
 * Set timeout to socket
 */
void set_socket_timeout(int * fd) {
    struct timeval timeout;      
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    setsockopt (*fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt (*fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
}

/*
 * Reads a single ARP reply from fd.
 * Return 0 on success.
 */
int read_arp(int fd) {
    unsigned char buffer[BUF_SIZE];
    /* Receive a message from a socket */
    ssize_t length = recv(fd, buffer, BUF_SIZE, 0);

    if (length == -1)
        return errno;
    
    /* This is an Ethernet frame header. */
    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);

    /* The ntohs() function convert values between host and network byte order */
    if (ntohs(rcv_resp->h_proto) != PROTO_ARP)
        return NOT_ARP_PACKET;

    if (ntohs(arp_resp->opcode) != ARP_REPLY)
        return NOT_ARP_REPLY;

    /* Internet address. */
    struct in_addr sender_a;
    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->sender_ip, sizeof(uint32_t));

    print_arp_packet(arp_resp);
    active_host++;

    return NO_ERROR;
}

/*
 * Sample code that sends an ARP who-has request on
 * interface <ifname> to IPv4 address <ip>.
 * Returns 0 on success.
 */
int test_arping(const char *ifname, uint32_t dst) {
    int err = 0;
    uint32_t src;
    int ifindex;
    char mac[MAC_LENGTH];

    if (dst == 0 || dst == 0xffffffff)
        return INVALID_IP;

    err = get_if_info(ifname, &src, mac, &ifindex);
    if (err)
        return err;

    int arp_fd;
    err = bind_arp(ifindex, &arp_fd);
    if (err)
        return err;

    set_socket_timeout(&arp_fd);
    err = send_arp_request(arp_fd, ifindex, mac, src, invert_IP(dst));
    if (err) {
        close(arp_fd);
        arp_fd = 0;
        return err;
    }

    while(1) {
        if (read_arp(arp_fd) != 0) 
            perror("");
        break;
    }

    close(arp_fd);
    return NO_ERROR;
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    char *subnet = NULL;
    unsigned req_timeout = 0;
    int arg;

    while ((arg = getopt(argc, argv, "i:s:t:h")) != -1) {
        switch (arg) {
            case 'i':
                interface = optarg;
                break;
            case 's':
                subnet = optarg;
                break;
            case 't':
                req_timeout = atoi(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (interface == NULL)
        ERROR(INVALID_INTERFACE);

    ERROR(check_existent_interface(interface));

    if (subnet == NULL)
        ERROR(INVALID_SUBNET);

    struct subnet *snet = parse_subnet(subnet);

    if (snet == NULL) 
        ERROR(INVALID_SUBNET);

    char * start = cast_uint_to_IPv4(snet->start);
    char * end = cast_uint_to_IPv4(snet->end);
    char * mask = cast_uint_to_IPv4(snet->mask);

    printf("###############################\n");
    printf("Subnet begins at: %s\n", start);
    printf("Subnet ends at: %s\n", end);
    printf("Subnet mask is: %s\n", mask);
    printf("Host to discover: %d\n", (snet->end - snet->start) + 1);
    printf("###############################\n");

    free(start);
    free(end);
    free(mask);

    char * ip;
    unsigned _begin = snet->start;
    unsigned _end = snet->end;
    free(snet);

    for(uint i = _begin; i <= _end; i++) {
        ip = cast_uint_to_IPv4(i);
        printf("\nSending ARP packet to: %s ...\n\n", ip);
        free(ip);
        ERROR(test_arping(interface, i));
        printf("\n###############################\n");
        sleep(req_timeout);
    }

    printf("Active HOST = %u\n", active_host);
    return 0;
}
