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

#define ERROR_NONE      0                  // Error Codes
#define ERROR_P_MISSING 1
#define ERROR_BAD_P     2
#define ERROR_NO_PROTO  3
#define ERROR_NO_PERM   4
#define ERROR_SND_FAIL  5
#define ERROR_RCV_FAIL  6

#define MAXPACKET       4096               // Max packet size

/* --------------------- */
/* Property Declarations */
/* --------------------- */

struct  sockaddr        whereto;           // Who to ping
int                     datalen;           // How much data 
int                     s;                 // Socket file descriptor
struct  sockaddr_in     from;              // The source address
int                     ident;             // Identifier
struct  protoent       *proto;             // The protocol
u_char                  packet[MAXPACKET]; // Packet buffer for reply

/* --------------------- */
/* Function declarations */
/* --------------------- */

// Console Functions
#define clear()     printf("\033[2J\033[H");

// ICMP Functions
void    ping        ( char* addr_p           );
int     in_cksum    ( u_short *addr, int len );
void    recv_echo   (   /* No parameter */   );
int     ip_valid    ( char *ip               );

// UI Functions
void    print_tb    ( char* title            );
void    print_sep   (   /* No parameter */   );
void    print_usage ( char* exe, char* r     );

/* --------------------- */
/*       Main Code       */
/* --------------------- */

int main (int argc, char **argv)
{
    clear();

    print_tb(
        "Test ICMP Packet Sender\n| By Nathan Fiscaletti\n| v0.1.1 - July, 2017"
    );
    printf("\n");

    if (argc < 2) {
        print_usage(argv[0], "Missing parameter 'ip'");
        exit(ERROR_P_MISSING);
    }

    if (! ip_valid(argv[1])) {
        print_usage(argv[0], "IP Address invalid.");
        exit(ERROR_BAD_P);
    }

    ping(argv[1]);
    recv_echo();

    printf("\n");
    print_tb("Done.");

    exit(ERROR_NONE);
}

void ping (char* addr_p)
{
    struct  sockaddr_in    *to = (struct sockaddr_in *) &whereto;
    bzero((char *)&whereto, sizeof(struct sockaddr_in) );

    to->sin_family = AF_INET;
    to->sin_addr.s_addr = inet_addr(addr_p);

    datalen = 10;

    if ((proto = getprotobyname("icmp")) == NULL) {
        fprintf(stderr, "icmp: unknown protocol\n");
        exit(ERROR_NO_PROTO);
    }

    if ((s = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) {
        perror("ping: socket");
        exit(ERROR_NO_PERM);
    }

    ident = getpid() & 0xFFFF;

    u_char outpack[MAXPACKET];
    struct icmp *icp = (struct icmp *) outpack;
    int i, cc;
    struct timeval *tp = (struct timeval *) &outpack[8];
    u_char *datap = &outpack[8+sizeof(struct timeval)];

    icp->icmp_type = ICMP_ECHO;
    icp->icmp_code = 0;
    icp->icmp_cksum = 0;
    icp->icmp_seq = 1;
    icp->icmp_id = ident;

    cc = datalen+8;             /* skips ICMP portion */

    for( i=8; i<datalen; i++)   /* skip 8 for time */
        *datap++ = i;

    /* Compute ICMP checksum here */
    icp->icmp_cksum = in_cksum( (u_short*)icp, cc );

    print_tb("Sending ICMP Echo Request");
    printf("| Destination IP : %s\n", addr_p);
    printf("| ICMP CkSum     : %i\n", icp->icmp_cksum);
    print_sep();

    i = sendto( s, outpack, cc, 0, &whereto, sizeof(struct sockaddr_in) );
    
    if( i < 0 ) {
        printf("| Packet Sent    : [ FAIL ]\n");
        print_sep();
        exit(ERROR_SND_FAIL);
    }

    printf("| Packet Sent    : [ SUCCESS ]\n");
    print_sep();
    printf("\n");
}

void recv_echo ()
{
    int len = sizeof (packet);
    int fromlen = sizeof (from);
    int cc;
    int fdmask = 1 << s;

    if ( (cc=recvfrom(
                 s, packet, len, 0, 
                 (struct sockaddr *)&from, (socklen_t*)&fromlen)) < 0) {
        printf("error: ping: recvfrom, errno: %i", errno);
        exit(ERROR_RCV_FAIL);
    } else {
        struct ip *ip;
        struct icmp *icp;

        ip = (struct ip *) packet;
        int hlen = ip->ip_hl << 2;
        icp = (struct icmp *) (packet + hlen);

        char out_src[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->ip_src.s_addr), out_src, INET_ADDRSTRLEN);

        char out_dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->ip_dst.s_addr), out_dst, INET_ADDRSTRLEN);

        print_tb("ICMP Echo Reply");
        printf("| Source IP      : %s \n", out_src);
        printf("| Destination IP : %s \n", out_dst);
        printf("| ICMP CkSum     : %i \n", icp->icmp_cksum);
        printf("| Packet Length  : %i \n", cc);
        print_sep();
    }
}

void print_sep ()
{
    printf("+--------------------------------\n");
}

void print_tb (char* title)
{
    print_sep();
    printf("| ");
    printf("%s", title);
    printf("\n");
    print_sep();
}

void print_usage (char* exe, char* r)
{
    print_tb("Invalid Invocation");
    printf("| Reason: ");
    printf("%s\n", r);
    printf("| \n");
    printf("| Usage\n");
    printf("| sudo ");
    printf("%s", exe);
    printf(" <ip>\n");
    print_sep();
    printf("\n");
}

int ip_valid (char *ip)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

int in_cksum (u_short *addr, int len)
{
    int nleft = len;
    u_short *w = addr;
    u_short answer;
    int sum = 0;

    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while( nleft > 1 )  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if( nleft == 1 ) {
        u_short u = 0;

        *(u_char *)(&u) = *(u_char *)w ;
        sum += u;
    }

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}

