#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <signal.h>

#define BUFFER_SIZE 1514

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
    const char*             interface;
} g_all;

extern g_all all;

void	*ft_memcpy(void *dest, const void *src, size_t n);
char *delete_double_point(char *mac);
void str_to_ip(const char *str, unsigned char *ip);
void    exit_msg(char *str);
int		ft_strncmp(const char *s1, const char *s2, size_t n);
int		ft_strlen(char *s);
int		ft_isalnum(int c);
int		ft_isdigit(int c);
int     check_mac_adress(char *str);
void     check_ip_adress(char *str);
void    check_arg(int argc, char **argv);
void    verbose_print();