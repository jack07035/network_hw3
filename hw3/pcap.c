#define __FAVOR_BSD
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>
#define MAC_ADDRSTRLEN 2*6+5+1

struct alldata{
    int num;
    char ip[300];
};

int flag=0;
int flags=0;

int count = 0;
int looksize =0;

struct alldata data[1500];

void dump_udp(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    u_int16_t source_port = ntohs(udp->uh_sport);
    u_int16_t destination_port = ntohs(udp->uh_dport);
    u_int16_t len = ntohs(udp->uh_ulen);
    u_int16_t checksum = ntohs(udp->uh_sum);

    printf("\n");
    printf("Protocol: \t\t\tUDP\n");
    printf("Source Port:     \t\t%u\n", source_port);
    printf("Destination Port:\t\t%u\n", destination_port);

}

void dump_tcp(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    //copy header
    u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);
    u_int32_t sequence = ntohl(tcp->th_seq);
    u_int32_t ack = ntohl(tcp->th_ack);
    u_int8_t header_len = tcp->th_off << 2;
    u_int8_t flags = tcp->th_flags;
    u_int16_t window = ntohs(tcp->th_win);
    u_int16_t checksum = ntohs(tcp->th_sum);
    u_int16_t urgent = ntohs(tcp->th_urp);

    //print
    printf("\n");
    printf("Protocol: \t\t\tTCP\n");
    printf("Source Port:     \t\t%u\n", source_port);
    printf("Destination Port:\t\t%u\n",destination_port);

}

char *mac_ntoa(u_char *d) {
    static char str[MAC_ADDRSTRLEN];

    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return str;
}

char *ip_ntoa(void *i) {
    static char str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, i, str, sizeof(str));

    return str;
}

void dump_ip(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    u_int version = ip->ip_v;
    u_int header_len = ip->ip_hl << 2;
    u_char tos = ip->ip_tos;
    u_int16_t total_len = ntohs(ip->ip_len);
    u_int16_t id = ntohs(ip->ip_id);
    u_int16_t offset = ntohs(ip->ip_off);
    u_char ttl = ip->ip_ttl;
    u_char protocol = ip->ip_p;
    u_int16_t checksum = ntohs(ip->ip_sum);

    //print
    printf("\n");
    printf("Protocol: \t\t\tIP\n");
    printf("Source IP Address:     \t\t%s\n",  ip_ntoa(&ip->ip_src));
    printf("Destination IP Address:\t\t%s\n", ip_ntoa(&ip->ip_dst));


    switch (protocol) {
        case IPPROTO_UDP:
            dump_udp(length, content);
            break;

        case IPPROTO_TCP:
            dump_tcp(length, content);
            break;
    }
}

void getdata(u_char *arg, const struct pcap_pkthdr *header, const u_char *content)
{
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    u_char protocol = ip->ip_p;

    switch (protocol) {
        case IPPROTO_UDP:
            if(flag == 1)
            {
                return;
            }
            break;

        case IPPROTO_TCP:
            if(flag == 2)
            {
                return ;
            }
            break;
    }

    if((flags == 1&&header->len > looksize)||(flags == 2&&header->len < looksize))
    {
        return ;
    }

    int i;
    count++;
    printf("\n");
    printf("---------------------------------------------------------\n");
    printf("No. %d\n",count);
    printf("Time: \t\t\t\t%s", ctime((const time_t *)&header->ts.tv_sec)); 
    printf("Length: \t\t\t%d bytes\n", header->len);

    struct ether_header *ethernet = (struct ether_header *)content;
    char dst_mac_addr[MAC_ADDRSTRLEN] = {};
    char src_mac_addr[MAC_ADDRSTRLEN] = {};
    u_int16_t type;

    strncpy(dst_mac_addr, mac_ntoa(ethernet->ether_dhost), sizeof(dst_mac_addr));
    strncpy(src_mac_addr, mac_ntoa(ethernet->ether_shost), sizeof(src_mac_addr));
    type = ntohs(ethernet->ether_type);

    printf("Source MAC Address:     \t%s\n", src_mac_addr);
    printf("Destination MAC Address:\t%s\n", dst_mac_addr);
    if(type>=1500)
    {
        printf("Ethernet Type:    \t\t0x%04x\n", type);
    }

    if(type == ETHERTYPE_IP)
    {
        dump_ip(header->caplen, content);
    }
    
}


int main(int argc,char *argv[])
{
    int i =0;
    for(i=0;i<argc;i++)
    {
        if(strcmp(argv[i],"-help")==0)
        {
            printf("\n-n    \tto see first n data\n");
            printf("-t    \tonly see tcp data\n");
            printf("-u    \tonly see udp data\n");
            printf("-small\tonly see data length less than \n");
            printf("-big  \tonly see data length big than \n\n");
            exit(1);
        }
    }

    memset(data,0,sizeof(data));

    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = NULL;

    device = pcap_lookupdev(errbuf);

    if(!device) 
    {
        fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
        exit(1);
    }
    printf("Sniffing: %s\n", device);

    pcap_t *handle=NULL;

    handle = pcap_open_live(device, 65535, 1, 1, errbuf);
    if(!handle)
    {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    if(argc > 1)
    {
        char input[100];
        memset(input,'\0',100);

        strcpy(input,argv[1]);

        handle = pcap_open_offline(input,errbuf);
        if(!handle)
        {
            fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
			exit(1);
        }
        printf("%s opened success !\n", input);
    }

    int lnum=-1;

    for(i=0;i<argc;i++)
    {
        if(strcmp(argv[i],"-n")==0)
        {
            lnum = atoi(argv[i+1]);
        }
        if(strcmp(argv[i],"-small")==0)
        {
            looksize = atoi(argv[i+1]);
            flags = 1;
        }
        if(strcmp(argv[i],"-big")==0)
        {
            looksize = atoi(argv[i+1]);
            flags = 2;
        }
        if(strcmp(argv[i],"-u")==0)
        {
            flag=2;
        }
        if(strcmp(argv[i],"-t")==0)
        {
            flag=1;
        }
    }

    pcap_loop(handle,lnum,getdata,0);

    pcap_close(handle);

}