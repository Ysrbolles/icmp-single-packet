/**
 * ICMP Packet Test
 * 
 * Adapted from https://bit.ly/2KrzYnJ
 * (See license in original file)
 *  
 * This file will send an ICMP Echo Request packet 
 * over a raw C socket and wait for a response on 
 * the socket of type ICMP echo reply. 
 *  
 * The raw socket used to send the ICMP Echo Request 
 * packet disables IP_HDRINCL so that we can instead 
 * build our own IP header for the packet. 
 *
 * @author Nathan Fiscaletti
 */

/* --------------------- */
/*       Includes        */
/* --------------------- */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <netdb.h>

#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <sys/socket.h>
#include <arpa/inet.h>

/* --------------------- */
/* Constant Declarations */
/* --------------------- */

#define EXIT_SUCCESS    0
#define ERROR_P_MISSING 1
#define ERROR_BAD_P     2
#define ERROR_NO_PROTO  3
#define ERROR_NO_PERM   4
#define ERROR_SND_FAIL  5
#define ERROR_RCV_FAIL  6
#define ERROR_MAL_PCKT  7
#define ERROR_SSO_FAIL  8

#define ICMP_ECHOREPLY  0
#define ICMP_ECHOREQEST 8
#define ICMP_ECHO_LEN   sizeof(struct ip) +\
                        sizeof(struct icmp)

/* --------------------- */
/*   Type Declarations   */
/* --------------------- */

typedef char             c;
typedef unsigned char   uc;
typedef uint16_t       u16;
typedef uint32_t       u32;

/* --------------------- */
/* Property Declarations */
/* --------------------- */

int                      s;     // Socket file descriptor
int16_t      dump_validate;     // The ID used for ICMP (reply/req)

/* --------------------- */
/* Function declarations */
/* --------------------- */

// Console Functions
#define clear()     printf("\033[2J\033[H");
void    fatal       ( c* message, int code            );
void    v_cli       ( int argc, c **argv              );

// ICMP Functions
void    ping        ( c* src_addr, c* dst_addr        );
int     icmp_cksum  ( u16 *buffer, u32 size           );
u_short ip_cksum    ( u_short *buf, int nwords        );
void    recv_echo   (   /* No parameter */            );
int     ip_valid    ( c *ip                           );
void    build_pack  ( uc *outpack, c* src, c* dst     );

// UI Functions
void    print_tb    ( c* title                        );
void    print_sep   (   /* No parameter */            );
void    print_usage ( c* exe, c* r                    );
void    disp_packet ( uc* packet, size_t len          );

/* --------------------- */
/*       Main Code       */
/* --------------------- */

int main (int argc, c **argv)
{
    clear();
    v_cli(argc, argv);
    ping(argv[1], argv[2]);
    recv_echo();
    printf("\n");
    print_tb("Done.");
    exit(EXIT_SUCCESS);
}

void ping (c* src_addr, c* dst_addr)
{
    struct  sockaddr        whereto;
    struct  protoent       *proto;
    struct  sockaddr_in    *to = (struct sockaddr_in *) &whereto;

    bzero((c *)&whereto, sizeof(struct sockaddr_in) );
    to->sin_family = AF_INET;
    to->sin_addr.s_addr = inet_addr(dst_addr);

    if ((proto = getprotobyname("icmp")) == NULL) {
        fatal("ICMP: Unknown Protocol.", ERROR_NO_PROTO);
    }

    if ((s = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) {
        fatal("SOCKET: No permission.", ERROR_NO_PERM);
    }

    uc *outpack = malloc(ICMP_ECHO_LEN);

    build_pack(outpack, src_addr, dst_addr);

    struct ip *ip    = (struct ip*)    outpack;
    struct icmp *icp = (struct icmp *) (outpack + sizeof(struct ip));

    print_tb("Sending ICMP Echo Request");
    printf("| Source IP      : %s\n",     src_addr);
    printf("| Destination IP : %s\n",     dst_addr);
    printf("| ICMP CkSum     : 0x%02X\n", ntohs(icp->icmp_cksum));
    printf("| Buffer Length  : %lu\n",    sizeof(outpack));
    print_sep();

    disp_packet(outpack, ip->ip_len);

    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
        fatal("Failed to set IP_HDRINCL sockopt.", ERROR_SSO_FAIL);
    }

    int str = sendto(s, outpack, ip->ip_len, 0, 
                     &whereto, sizeof(struct sockaddr_in));

    if( str < 0 ) {
        printf("| Packet Sent    : [ FAIL ]\n");
        printf("| errno          : %i\n", errno);
        print_sep();
        exit(ERROR_SND_FAIL);
    }

    free(outpack);

    printf("| Packet Sent    : [ SUCCESS ]\n");
    print_sep();
    printf("\n");
}

void recv_echo ()
{
    struct  sockaddr_in     from;
    uc*                      packet  = malloc(ICMP_ECHO_LEN);
    int                     fromlen = sizeof (from);
    int                     cc;

    if ( (cc=recvfrom(
                 s, packet, ICMP_ECHO_LEN, 0,
                 (struct sockaddr *)&from, (socklen_t*)&fromlen)) < 0) {
        free(packet);
        fatal("PING: recvfrom failed.", ERROR_RCV_FAIL);
    } else {
        struct ip   *ip;
        struct icmp *icp;

        ip = (struct ip *) packet;
        int hlen = ip->ip_hl << 2;
        icp = (struct icmp *) (packet + hlen);

        c out_src[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->ip_src.s_addr), out_src, INET_ADDRSTRLEN);

        c out_dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->ip_dst.s_addr), out_dst, INET_ADDRSTRLEN);

        // Validate the ICMP packet
        if (! (
            ip->ip_p            == IPPROTO_ICMP
         && icp->icmp_type      == ICMP_ECHOREPLY
         && ntohs(icp->icmp_id) == dump_validate
        )) {
            print_sep();
            disp_packet(packet, cc);
            printf("\n");
            free(packet);
            fatal("Received a malformed packet.", ERROR_MAL_PCKT);
        }

        print_tb("ICMP Echo Reply");
        printf("| Source IP      : %s \n", out_src);
        printf("| Destination IP : %s \n", out_dst);
        printf("| ICMP CkSum     : 0x%02X \n", ntohs(icp->icmp_cksum));
        printf("| Packet Length  : %i \n", cc);
        print_sep();
        disp_packet(packet, cc);
        free(packet);
    }
}

void build_pack ( uc *outpack, c* src, c* dst )
{
    dump_validate     = rand();

    struct ip *ip     = (struct ip*)    outpack;
    struct icmp *icp  = (struct icmp *) (outpack + sizeof(struct ip));

    ip->ip_hl         = 5; // Bit field, 5 = 20 bytes
    ip->ip_v          = 4;
    ip->ip_tos        = 0;
    ip->ip_len        = sizeof(struct ip) + sizeof(struct icmp);
    ip->ip_id         = 0;
    ip->ip_off        = 0;
    ip->ip_ttl        = 255;
    ip->ip_p          = IPPROTO_ICMP;
    ip->ip_sum        = 0;
    ip->ip_src.s_addr = inet_addr(src);
    ip->ip_dst.s_addr = inet_addr(dst);

    icp->icmp_type    = ICMP_ECHOREQEST;
    icp->icmp_code    = 0;
    icp->icmp_cksum   = 0;
    icp->icmp_seq     = 1;
    icp->icmp_id      = htons(dump_validate);

    // Compute checksums
    ip->ip_sum      = ip_cksum   ((u_short*)ip , ip->ip_len         );
    icp->icmp_cksum = icmp_cksum ((u_short*)icp, sizeof(struct icmp));
}

void print_sep ()
{
    printf("+--------------------------------\n");
}

void print_tb (c* title)
{
    print_sep();
    printf("| ");
    printf("%s", title);
    printf("\n");
    print_sep();
}

void print_usage (c* exe, c* r)
{
    print_tb("Invalid Invocation");
    printf("| Reason: ");
    printf("%s\n", r);
    printf("| \n");
    printf("| Usage\n");
    printf("| sudo ");
    printf("%s", exe);
    printf(" <src> <dst>\n");
    print_sep();
    printf("\n");
}

int ip_valid (c *ip)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

void fatal(c* message, int code) 
{
    c title[32];
    sprintf(title, "Error - EN: %i, EC: %i", errno, code);
    print_tb(title);
    printf("| %s\n", message);
    print_sep();
    exit(code);
}

void disp_packet(uc* packet, size_t len)
{
    c title[32];
    sprintf(title, "Packet - Len %zu\n", len);
    printf("| %s", title);
    print_sep();
    printf("| ");
    int i;
    for (i=0;i<len;i++) {
        printf("%02X ", ((unsigned int)packet[i]));
        if ((i+1) % 10 == 0) {
            printf("\n");
            if (i != (len -1))
                printf("| ");
        }
    }
    printf("\n");
    print_sep();
}

void v_cli(int argc, c **argv)
{
    if (argc < 2) {
        print_usage(argv[0], "Missing parameter 'src'");
        exit(ERROR_P_MISSING);
    }

    if (argc < 3) {
        print_usage(argv[0], "Missing parameter 'dst'");
        exit(ERROR_P_MISSING);
    }

    if (! ip_valid(argv[1]) || ! ip_valid(argv[2])) {
        print_usage(argv[0], "IP Address invalid.");
        exit(ERROR_BAD_P);
    }
}

int icmp_cksum (u16 *buffer, u32 size)
{
    unsigned long cksum=0;
    while(size >1) 
    {
        cksum+=*buffer++;
        size -=sizeof(unsigned short);
    }
    if(size ) 
    {
        cksum += *(uc*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (uint16_t)(~cksum);
}

u_short ip_cksum (u_short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}
