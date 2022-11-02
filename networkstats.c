#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <string.h>
#define SIZE_ETHERNET 14

/* IP header */
struct sniff_ip
{
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                /* total length */
    u_short ip_id;                 /* identification */
    u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000               /* reserved fragment flag */
#define IP_DF 0x4000               /* don't fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp
{
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;   /* sequence number */
    tcp_seq th_ack;   /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

struct sniff_udp
{
    u_short sport; //source port
    u_short dport; //destination port
    u_short len;   //datagram length
    u_short crc;   //checksum
};

/* This function can be used as a callback for pcap_loop() */
void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet)
{
    struct ether_header *eth_header;
    struct sniff_tcp *t_header;
    struct sniff_ip *ip_header;
    struct sniff_udp *udp_header;
    eth_header = (struct ether_header *)packet;
    ip_header = (struct ip *)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip_header) * 4;

    printf("\t\t\t--------PACKET--------\n");
    if (ip_header->ip_p == 6)
        printf("**\t\tPROTOCOL : TCP\n");
    if (ip_header->ip_p == 17)
    {
        printf("**\t\tPROTOCOL : UDP\n");
    }
    printf("**\t\tPacket Length : %d\n", header->len);
    printf("**\t\tIP Length : %d\n", ip_header->ip_len / 256);
    printf("**\t\tIP Header Length : %d\n", size_ip);
    //TCP PACKET
    if (ip_header->ip_p == 6)
    {
        t_header = (struct tcp_hdr *)(packet + SIZE_ETHERNET + size_ip);
        u_int size_tcp = TH_OFF(t_header) * 4;
        const char *payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        printf("**\t\tTCP Header Length : %d\n", size_tcp);
        printf("**\t\tTCP Segment Length : %d\n", ip_header->ip_len / 256 - (size_ip + size_tcp));
        printf("**\t\tSource Port : %u\n**\t\tDesination Port : %u\n", t_header->th_sport, t_header->th_dport);
        printf("**\t\tFLAGS : 0x%x\n", t_header->th_flags);
        printf("**\t\tSequence Number : %u\n", t_header->th_seq);
        printf("**\t\tAcknowledgement Number (Ack) : %u\n\n\n", t_header->th_ack);
    }
    //UDP PACKET
    else if (ip_header->ip_p == 17)
    {
        udp_header = (struct udp_hdr *)(packet + SIZE_ETHERNET + size_ip);
        printf("**\t\tSource Port : %u\n**\t\tDestination Port : %u\n", udp_header->sport, udp_header->dport);
        printf("**\t\tUDP Datagram Length : %u\n", udp_header->len / 256);
    }
    printf("\t\t----------------------------------------\n");
}

void fileParser()
{
    FILE *fin;
    fin = fopen("output.txt", "r");
    char c = fgetc(fin);
    char buf[256];
    char fileSize[256], dataSpeed[256], bitSpeed[256], packetRate[256];
    int count = 0;
    int i = 0, j = 0;
    float size, speed, Mbps, prate;
    char temp[256];
    while (fgets(buf, sizeof(buf), fin) != NULL)
    {
        switch (count)
        {
        case 11:
            i = 0, j = 0;
            temp[0] = '\0';
            strcpy(temp, buf);
            while (temp[i] != ':')
                i++;
            i++;
            while (temp[i] == ' ')
                i++;
            while (temp[i] != ' ')
            {
                dataSpeed[j] = temp[i];
                j++;
                i++;
            }
            speed = atof(dataSpeed);
            printf("**\t\tAVERAGE SPEED(MBps)   : %4.2fMBps\n", speed);
            count++;
            break;
        case 12:
            i = 0, j = 0;
            temp[0] = '\0';
            strcpy(temp, buf);
            while (temp[i] != ':')
                i++;
            i++;
            while (temp[i] == ' ')
                i++;
            while (temp[i] != ' ')
            {
                bitSpeed[j] = temp[i];
                i++;
                j++;
            }
            Mbps = atof(bitSpeed);
            printf("**\t\tAVERAGE SPEED(Mbps)   : %4.2f Mbps\n", Mbps);
            count++;
            break;
        case 13:
            i = 0, j = 0;
            temp[0] = '\0';
            strcpy(temp, buf);
            while (temp[i] != ':')
                i++;
            i++;
            while (temp[i] == ' ')
                i++;

            while (temp[i] != ' ')
            {
                fileSize[j] = temp[i];
                j++;
                i++;
            }
            size = atof(fileSize);
            printf("**\t\tAVERAGE PACKET SIZE   : %4.2f bytes\n", size);
            count++;
            break;
        case 14:
            i = 0, j = 0;
            temp[0] = '\0';
            strcpy(temp, buf);
            while (temp[i] != ':')
                i++;
            i++;
            while (temp[i] == ' ')
                i++;

            while (temp[i] != ' ')
            {
                packetRate[j] = temp[i];
                j++;
                i++;
            }
            prate = atof(packetRate);
            printf("**\t\tAVERAGE PACKET RATE/s : %4.2f kpackets/s\n", prate);
            count++;
            break;
        default:
            count++;
        }
    }
    printf("**\t\tAVERAGE RTT           : %f seconds\n", (size * 2) / (speed * 1048576));
}

void menu(){
    system("clear");
    printf("\n******************************* MENU *******************************");
    printf("\n\n**   Enter the file name with the .pcap extension for analysis    **");
    printf("\n\n**     ==>   ");
}

int main(int argc, char **argv)
{
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *device;
    device = pcap_lookupdev(error_buffer);

    int snapshot_len = 1028;
    int promiscuous = 0;
    int timeout = 1000;

    char fileName[100];
    menu();
    scanf("%s", fileName);
    printf("\n\n******************* The packets received are : *********************\n\n");

    char command[100];
    sprintf(command, "capinfos %s > ./output.txt", fileName);
    system(command);
    handle = pcap_open_offline(fileName, error_buffer);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return 2;
    }
    pcap_loop(handle, 0, my_packet_handler, NULL);
    pcap_close(handle);
    printf("\n\n********************** FINAL NETWORK STATISTICS **********************\n\n");
    fileParser();
    printf("\n\n***********************************************************************\n\n");
    return 0;
}