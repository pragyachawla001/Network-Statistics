#include <pcap.h>

#include <stdio.h>

#include <string.h>

#include <stdlib.h>

#include <ctype.h>

#include <errno.h>

#include <sys/types.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#define APP_NAME "sniffex"
#define APP_DESC "Sniffer example using libpcap"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
  u_char ip_vhl; /* version << 4 | header length >> 2 */
  u_char ip_tos; /* type of service */
  u_short ip_len; /* total length */
  u_short ip_id; /* identification */
  u_short ip_off; /* fragment offset field */
  #define IP_RF 0x8000 /* reserved fragment flag */
  #define IP_DF 0x4000 /* don't fragment flag */
  #define IP_MF 0x2000 /* more fragments flag */
  #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
  u_char ip_ttl; /* time to live */
  u_char ip_p; /* protocol */
  u_short ip_sum; /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)(((ip) -> ip_vhl) & 0x0f)
#define IP_V(ip)(((ip) -> ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  tcp_seq th_seq; /* sequence number */
  tcp_seq th_ack; /* acknowledgement number */
  u_char th_offx2; /* data offset, rsvd */
  #define TH_OFF(th)(((th) -> th_offx2 & 0xf0) >> 4)
  u_char th_flags;
  #define TH_FIN 0x01
  #define TH_SYN 0x02
  #define TH_RST 0x04
  #define TH_PUSH 0x08
  #define TH_ACK 0x10
  #define TH_URG 0x20
  #define TH_ECE 0x40
  #define TH_CWR 0x80
  #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};

struct sniff_udp {
  u_short sport; //source port
  u_short dport; //destination port
  u_short len; //datagram length
  u_short crc; //checksum
};

void got_packet(u_char * args,
  const struct pcap_pkthdr * header,
    const u_char * packet);

void print_payload(const u_char * payload, int len);

void print_hex_ascii_line(const u_char * payload, int len, int offset);

void print_app_usage(void);

/*
 * print help text
 */
void print_app_usage(void) {

  printf("Usage: %s [interface]\n", APP_NAME);
  printf("\n");
  printf("Options:\n");
  printf("    interface    Listen on <interface> for packets.\n");
  printf("\n");
  return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char * payload, int len, int offset) {

  int i;
  int gap;
  const u_char * ch;

  /* offset */
  printf("%05d   ", offset);

  /* hex */
  ch = payload;
  for (i = 0; i < len; i++) {
    printf("%02x ", * ch);
    ch++;
    /* print extra space after 8th byte for visual aid */
    if (i == 7)
      printf(" ");
  }
  /* print space to handle line less than 8 bytes */
  if (len < 8)
    printf(" ");

  /* fill hex gap with spaces if not full line */
  if (len < 16) {
    gap = 16 - len;
    for (i = 0; i < gap; i++) {
      printf("   ");
    }
  }
  printf("   ");

  /* ascii (if printable) */
  ch = payload;
  for (i = 0; i < len; i++) {
    if (isprint( * ch))
      printf("%c", * ch);
    else
      printf(".");
    ch++;
  }

  printf("\n");

  return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char * payload, int len) {

  int len_rem = len;
  int line_width = 16; /* number of bytes per line */
  int line_len;
  int offset = 0; /* zero-based offset counter */
  const u_char * ch = payload;

  if (len <= 0)
    return;

  /* data fits on one line */
  if (len <= line_width) {
    printf("  \t\t");
    print_hex_ascii_line(ch, len, offset);
    return;
  }

  /* data spans multiple lines */
  while(1) {
    /* compute current line length */
    line_len = line_width % len_rem;
    /* print line */
    printf("  \t\t");
    print_hex_ascii_line(ch, line_len, offset);
    /* compute total remaining */
    len_rem = len_rem - line_len;
    /* shift pointer to remaining bytes to print */
    ch = ch + line_len;
    /* add offset */
    offset = offset + line_width;
    /* check if we have line width chars or less */
    if (len_rem <= line_width) {
      /* print last line and get out */
      printf("  \t\t");
      print_hex_ascii_line(ch, len_rem, offset);
      break;
    }
  }

  return;
}

/*
 * dissect/print packet
 */
void got_packet(u_char * args,
  const struct pcap_pkthdr * header,
    const u_char * packet) {

  static int count = 1; /* packet counter */

  /* declare pointers to packet headers */
  const struct sniff_ethernet * ethernet; /* The ethernet header [1] */
  const struct sniff_ip * ip; /* The IP header */
  const struct sniff_tcp * tcp; /* The TCP header */
  const char * payload; /* Packet payload */

  int size_ip;
  int size_tcp;
  int size_payload;

  printf("\t\t-------- PACKET [Number : %d] --------\n\n", count++);

  /* define ethernet header */
  ethernet = (struct sniff_ethernet * )(packet);

  /* define/compute ip header offset */
  ip = (struct sniff_ip * )(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip) * 4;
  if (size_ip < 20) {
    printf("**\t\tInvalid IP header length: %u bytes\n", size_ip);
    return;
  }

  /* print source and destination IP addresses */
  printf("**\t\tFrom IP : %s\n", inet_ntoa(ip -> ip_src));
  printf("**\t\tTo IP : %s\n", inet_ntoa(ip -> ip_dst));

  /* determine protocol */
  switch (ip -> ip_p) {
  case IPPROTO_TCP:
    printf("**\t\tProtocol : TCP\n");
    break;
  case IPPROTO_UDP:
    printf("**\t\tProtocol : UDP\n");
    break;
  case IPPROTO_ICMP:
    printf("**\t\tProtocol : ICMP\n");
    return;
  case IPPROTO_IP:
    printf("**\t\tProtocol : IP\n");
    return;
  default:
    printf("**\t\tProtocol : Unknown\n");
    return;
  }

  /* define/compute tcp header offset */
  if (ip -> ip_p == IPPROTO_UDP) {
    struct sniff_udp * udp;
    udp = (struct sniff_udp * )(packet + SIZE_ETHERNET + size_ip);
    printf("**\t\tSource Port : %u\n**\t\tDestination Port : %u\n", udp -> sport, udp -> dport);
    printf("**\t\tUDP Datagram Length : %u\n", udp -> len / 256);
  } else {

    tcp = (struct sniff_tcp * )(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
      printf("**\t\tInvalid TCP header length: %u bytes\n", size_tcp);
      return;
    }

    printf("**\t\tSource port : %d\n", ntohs(tcp -> th_sport));
    printf("**\t\tDestination port : %d\n", ntohs(tcp -> th_dport));

    printf("**\t\tPacket capture length : %d\n", header -> caplen);
    printf("**\t\tPacket total length : %d\n", header -> len);

    printf("**\t\tSequence number : %u\n", tcp -> th_seq);
    printf("**\t\tAcknowledgement number(Ack) : %u\n", tcp -> th_ack);

    /* define/compute tcp payload (segment) offset */
    payload = (u_char * )(packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip -> ip_len) - (size_ip + size_tcp);

    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
      printf("**\t\tPayload (%d bytes) : \n\n", size_payload);
      print_payload(payload, size_payload);
    }
  }
  printf("\n\t\t----------------------------------------\n\n");
  return;
}

void parse() {
  FILE * f;
  f = fopen("data.txt", "r");
  char c = fgetc(f);
  char buf[256];
  char temp[256];
  int count = 0;
  int i = 0, j = 0;
  float size, speed, Mbps, prate;
  for (int count = 0; fgets(buf, sizeof(buf), f) != NULL && count < 15; count++) {
    if (count < 11) {
      continue;
    }
    i = 0, j = 0;
    while (!isdigit(buf[i])) i++;
    while (buf[i] != ' ') {
      if (buf[i] != ',') {
        temp[j++] = buf[i];
      }
      i++;
    }
    temp[j++] = 0;
    if (count == 11) {
      speed = atof(temp);
      printf("**\t\tAVERAGE SPEED(MBps)   : %4.2f MBps\n", speed / (1024.0f));
    } else if (count == 12) {
      Mbps = atof(temp);
      printf("**\t\tAVERAGE SPEED(Mbps)   : %4.2f Mbps\n", Mbps / (1024.0f));
    } else if (count == 13) {
      size = atof(temp);
      printf("**\t\tAVERAGE PACKET SIZE   : %4.2f bytes\n", size);
    } else if (count == 14) {
      prate = atof(temp);
      printf("**\t\tAVERAGE PACKET RATE/s : %4.2f kpackets/s\n", prate);
    }
  }
  printf("**\t\tAVERAGE RTT           : %f seconds\n", size / (speed * 512));
}

void menu() {
  system("clear");
  printf("\n********************************* MENU ***********************************");
  printf("\n\n**     Enter the file name with the .pcap extension for analysis        **");
  printf("\n\n**       ==>   ");
}

int main(int argc, char ** argv) {
  char errbuf[PCAP_ERRBUF_SIZE]; /* error Temporary */
  pcap_t * handle; /* packet capture handle */

  char filter_exp[] = "ip"; /* filter expression [3] */
  struct bpf_program fp; /* compiled filter program (expression) */
  bpf_u_int32 mask = 0; /* subnet mask */
  bpf_u_int32 net = 0; /* ip */
  int num_packets = 0; /* number of packets to capture */

  char fileName[100];
  menu();
  scanf("%s", fileName);
  handle = pcap_open_offline(fileName, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device\n");
    exit(EXIT_FAILURE);
  }
  printf("\n**************************************************************************");
  printf("\n\n**     Enter number of packets to be sniffed (Enter 0 for all):         **");
  printf("\n\n**     ==>   ");
  scanf("%d", & num_packets);
  printf("\n**************************************************************************");
  if (num_packets == 0)
    printf("\n\n**     Number of packets : All\n");
  else
    printf("\n\n**     Number of packets : %d\n", num_packets);

  /* make sure we're capturing on an Ethernet device [2] */
  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Not an Ethernet\n");
    exit(EXIT_FAILURE);
  }
  printf("\n**************************************************************************\n\n");

  /* compile the filter expression */
  if (pcap_compile(handle, & fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n",
      filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* apply the compiled filter */
  if (pcap_setfilter(handle, & fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n",
      filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* now we can set our callback function */
  pcap_loop(handle, num_packets, got_packet, NULL);

  /* cleanup */
  pcap_freecode( & fp);
  pcap_close(handle);

  char command[200];
  sprintf(command, "capinfos %s > ./data.txt", fileName);
  system(command);
  printf("\n\n********************** FINAL NETWORK STATISTICS **********************\n\n");
  parse();
  printf("\n\n***********************************************************************\n\n");

  printf("\nCapture complete.\n\n");

  return 0;
}