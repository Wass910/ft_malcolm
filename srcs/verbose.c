#include "../inc/ft_malcolm.h"

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
