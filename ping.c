/* 
 *			P I N G . C
 *
 * Internet Control Message Protocol (ICMP) ipv4 dan ipv6.
 * Mengukur round-trip time dan packet loss.
 * Ping ini bisa menyesuaikan antara ipv4 atau ipv6 tergantung
 * jenis ip address yang diinput.
 *
 * Jika destination yang diinput adalah hostname, maka program
 * ping ini akan menggunakan ipv6 jika ada, jika tidak ada ipv6
 * maka ipv4 yang digunakan.
 *
 * Author:
 *	Dhani Setiawan (dhani.stx@gmail.com)
 *	PT. Transkon Jaya
 *	Februari, 2016
 *
 * Status:
 *      Working but several things need to be fixed.
 *      1. Set fallback to ipv4 if we have no ipv6 global unicast address.
 *      2. If source address set, icmp version needs to be adjusted
 *         according to source address version.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

unsigned int options;                    /* Options flags */
#define O_BRIEF         0x001
#define O_LOOP          0x002
#define O_IVAL          0x004
#define O_REPEAT        0x008
#define O_SRC           0x010
#define O_IPV6          0x020
#define O_IPV4          0x040

#define PROG_NAME       "ping"
#define MAXSIZE         10000
#define DEFDATALEN      100
#define MAXIPLEN        60
#define MAXICMPLEN      76
#define DEFRPT          5
#define MAXTRACK        64
#define BUFLEN          40

struct stats_st {               /* struct to hold ping stats */
        u_int   tx:16;
        u_int   rx:16;
        u_int   percent:8;
        u_int   min:8;
        u_int   max:8;
        u_int   avg:8;
} stats;

#define S_TRANSMIT      stats.tx
#define S_RCVD          stats.rx
#define S_PERCENT       stats.percent
#define S_MIN           stats.min
#define S_MAX           stats.max
#define S_AVG           stats.avg

u_char track[MAXTRACK];
#define A(bit)          track[(bit) >> 3]
#define B(bit)          (1 << ((bit) & 0x07))
#define SET(bit)        (A(bit) |= B(bit))
#define CLR(bit)        (A(bit) &= (~B(bit)))
#define TST(bit)        (A(bit) & B(bit))

#define AF              (options & O_IPV6) ? AF_INET6 : AF_INET
#define inet_ntop(x)    inet_ntop(AF, x, address, (socklen_t)BUFLEN)
#define ICMP_TYPE       (options & O_IPV6) ? ICMPV6_ECHO_REQUEST : ICMP_ECHO

/* protos */
void usage(void);
int pr(char *buf, int psize);
int pr6(char *buf, int psize);
static void sendping(int blah);
static void finish(int blah);
static int in_cksum(u_short *addr, int len);

/* vars */
int id;                         /* ping pid */
int nrepeat = DEFRPT;           /* send count */
u_short interval = 1;
int s;                          /* Socket file descriptor */
struct sockaddr_storage dst;    /* destination address */
struct sockaddr_storage *to;
char *address;
u_char *rcv_pkt;                /* received msg buffer */
u_char snd_pkt[MAXSIZE + 20];   /* send packet buffer */
int datalen = DEFDATALEN;       /* Packet size */
int timeout = 2;                /* timeout */
char REPLY = '!';
char TIMEOUT = '.';

int main(int argc, char *argv[])
{    
        char *h = NULL;
        struct protoent *protocol;
        struct timeval timeo;
        struct addrinfo *pingfrom;

        options &= 0;
        if (argc == 1) {
                usage();
                exit(2);
        }

        if (!(address = malloc((u_int)BUFLEN))) {
                fprintf(stderr, "Error malloc.\n");
                exit(2);
        }

        *argv++;
        while (*argv != NULL) {
                int arglen;
                if ((arglen = strlen(*argv)) > 100) {
                        fprintf(stderr, "Error: Argument too long.\n");
                        exit(2);
                }
        
                switch(*argv[0]) {
                        case 'r':
                                if (strncmp(*argv, "repeat", 
                                                arglen) == 0 &&
                                                arglen <= 6) {
                                        options |= O_REPEAT;
                                        *argv++;

                                        if (*argv == NULL) {
                                                fprintf(stderr,
                                                "repeat requires value\n");
                                                exit(2);
                                        } else
                                                if ((nrepeat = atoi(*argv)) == 0) {
                                                        fprintf(stderr, 
                                                                "repeat value not valid\n");
                                                        exit(2);
                                                }
                                } else {
                                        if (h == NULL)
                                                h = *argv;
                                        else {
                                                fprintf(stderr, "Unknown options %s.\n", *argv);
                                                exit(2);
                                        }
                                }

                                break;

                        case 'v':
                                if (strncmp(*argv, "verbose", arglen) == 0 &&
                                                arglen <= 7)
                                        options |= O_BRIEF;
                                else {
                                        if (h == NULL)
                                                h = *argv;
                                        else {
                                                fprintf(stderr, "Unknown options %s.\n", *argv);
                                                exit(2);
                                        }
                                }

                                break;

                        case 'i':
                                if (strncmp(*argv, "ipv", arglen) == 0 &&
                                                arglen <=3) {
                                        fprintf(stderr, "Ambiguous option %s:\n", *argv);
                                        fprintf(stderr, "  ipv6                 ping using ipv6 address\n");
                                        fprintf(stderr, "  ipv4                 ping using ipv4 address\n");
                                        fprintf(stderr, "  interval <n>         Send ping every n-second interval\n");
                                        exit(2);
                                
                                }
                                if (strncmp(*argv, "interval", arglen) == 0 &&
                                                arglen <= 8) {
                                        *argv++;
                                        if (*argv != NULL) {
                                                if ((interval = atoi(*argv)) == 0) {
                                                        fprintf(stderr, "Error: interval value is not valid.\n");
                                                        exit(2);
                                                }
                                                if (interval < 1) {
                                                        fprintf(stderr, "Error: minimum interval value is 1 second.\n");
                                                        exit(2);
                                                }
                                        } else {
                                                fprintf(stderr, "Error: interval requires value.\n");
                                                exit(2);
                                        }

                                        options |= O_IVAL;
                                } else if (strncmp(*argv, "ipv6", arglen) == 0 &&
                                                arglen <= 4) {
                                        options |= O_IPV6;
                                        options &= ~O_IPV4;
                                } else if (strncmp(*argv, "ipv4", arglen) == 0 &&
                                                arglen <= 4) {
                                        options |= O_IPV4;
                                        options &= ~O_IPV6;
                                } else {
                                        if (h == NULL)
                                                h = *argv;
                                        else {
                                                fprintf(stderr, "Unknown options %s.\n", *argv);
                                                exit(2);
                                        }
                                }

                                break;

                        case 'f':
                                if (strncmp(*argv, "forever", arglen) == 0 &&
                                                arglen <= 7) {
                                        options |= O_LOOP;
                                        options |= O_IVAL;
                                } else {
                                        if (h == NULL)
                                                h = *argv;
                                        else {
                                                fprintf(stderr, "Unknown options %s.\n", *argv);
                                                exit(2);
                                        }
                                }

                                break;

                        case 't':
                                if (strncmp(*argv, "timeout", arglen) == 0 &&
                                                arglen <= 7) {
                                        *argv++;
                                        if (*argv == NULL) {
                                                fprintf(stderr, "timeout requires value.\n");
                                                exit(2);
                                        }

                                        if ((timeout = atoi(*argv)) < 1) {
                                                fprintf(stderr, "Error: %s is not valid timeout value.\n",
                                                                *argv);
                                                exit(2);
                                        }

                                        if (timeout > 60) {
                                                fprintf(stderr, "Error: maximum timeout value is 60 seconds.\n");
                                                exit(2);
                                        }
                                } else {
                                        if (h == NULL)
                                                h = *argv;
                                        else {
                                                fprintf(stderr, "Unknown options %s.\n", *argv);
                                                exit(2);
                                        }
                                }

                                break;

                        case 's':
                                if (strlen(*argv) == 1) {
                                        fprintf(stderr, "Ambiguous options s, size or source?\n");
                                        exit(2);
                                }
                                if (strncmp(*argv, "size", arglen) == 0 &&
                                                arglen <= 4) {
                                        *argv++;
                                        if (*argv == NULL) {
                                                fprintf(stderr, "Error: size requires value.\n");
                                                exit (2);
                                        }

                                        if ((datalen = atoi(*argv)) == 0) {
                                                fprintf(stderr, "Error: %s is not valid size value.\n",
                                                        *argv);
                                                exit(2);
                                        }
                                        if (datalen > (MAXSIZE)) {
                                                fprintf(stderr, "Error: maximum allowed size is %d.\n",
                                                                MAXSIZE);
                                                exit(2);
                                        }
                                } else if (strncmp(*argv, "source", arglen) == 0 &&
                                                arglen <= 6) {
                                        *argv++;
                                        if (*argv == NULL) {
                                                fprintf(stderr, "Error: option source requires value.\n");
                                                exit(2);
                                        }
                                       
                                        if (getaddrinfo(*argv, NULL, NULL, &pingfrom) != 0) {
                                                fprintf(stderr, "Error: bad source address %s\n", *argv);
                                                exit(2);
                                        }
                                        options |= O_SRC;
                                } else {
                                        if (h == NULL)
                                                h = *argv;
                                        else {
                                                fprintf(stderr, "Unknown options %s.\n", *argv);
                                                exit(2);
                                        }
                                }

                                break;

                        default:
                                if (h == NULL)
                                        h = *argv;
                                else {
                                        fprintf(stderr, "Unknown options %s.\n", *argv);
                                        exit(2);
                                }
                }
         
                *argv++;
        }

        id = getpid() & 0xFFFF;

        if ((options & O_LOOP) && (options & O_REPEAT)) {
                fprintf(stderr, "Error: options conflict, forever and repeat.\n");
                exit(2);
        }
        
        to = NULL;
        memset(&dst, 0, sizeof(struct sockaddr_storage));
        struct addrinfo *res, *p;
                
        if (getaddrinfo(h, NULL, NULL, &res) != 0) {
                fprintf(stderr, "Error: dst host %s\n", h);
                exit(2);
        }
       
        struct sockaddr_in *addrv4tmp = NULL;
        for (p = res; p != NULL; p = p->ai_next) {
                if (options & O_IPV4) {
                        if(p->ai_family == AF_INET) {
                                to = (struct sockaddr_storage *)p->ai_addr;
                                break;
                        } else continue;
                } else if (options & O_IPV6) {
                        if (p->ai_family == AF_INET6) {
                                to = (struct sockaddr_storage *)p->ai_addr;
                                break;
                        } else continue;
                } else {
                        if (p->ai_family == AF_INET && addrv4tmp == NULL) {
                                addrv4tmp = (struct sockaddr_in *)p->ai_addr;
                                continue;
                        }
                        if (p->ai_family == AF_INET6) {
                                to = (struct sockaddr_storage *)p->ai_addr;
                                options |= O_IPV6;
                                break;
                        }
                }
        }
        
        if (to == NULL && addrv4tmp != NULL) {
                if (!(options & O_IPV6)) {
                        to = (struct sockaddr_storage *)addrv4tmp;
                        options &= ~O_IPV6;
                }
        }

        if ((options & O_IPV6) && (to == NULL || to->ss_family == AF_INET)) {
                fprintf(stderr, "Could not resolve ipv6 address for %s\n", h);
                exit(2);
        }
        if ((options & O_IPV4) && (to == NULL || to->ss_family == AF_INET6)) {
                fprintf(stderr, "Could not resolve ipv4 address for %s\n", h);
                exit(2);
        }

        memcpy(&dst, to, sizeof(struct sockaddr_storage));
        to = &dst;
        freeaddrinfo(res);
        
        if (options & O_IPV6)
                protocol = getprotobyname("ipv6-icmp");
        else
                protocol = getprotobyname("icmp");
        
        if (!protocol) {
                fprintf(stderr, "Error: Unknown protocol\n");
                exit(2);
        }
        
        if ((s = socket(AF, SOCK_RAW, protocol->p_proto)) < 0) {
                if (errno == EPERM)
                        fprintf(stderr, "Only root can create socket\n");
                else
                        fprintf(stderr, "Error creating socket\n");
                exit(2);
        }
        
        int plen = datalen + MAXIPLEN + MAXICMPLEN;

        rcv_pkt = malloc((u_int)plen);
        if (!rcv_pkt) {
                fprintf(stderr, "Error: memory allocation failed.\n");
                exit(2);
        }
        
        timeo.tv_sec = timeout;
        timeo.tv_usec = 0;

        u_short i;
        int addrlen = sizeof(struct sockaddr_storage);
        struct sockaddr_storage src;
        int sz;

        if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, 
                                &timeo, sizeof(struct timeval)) < 0) {
                fprintf(stderr, "Error set socket option.\n");
                exit(2);
        }

        if (options & O_SRC) {
                if ((AF) != pingfrom->ai_family) {
                        fprintf(stderr, "Error: ip version mismatch, source and destination address\n");
                        freeaddrinfo(pingfrom);
                        exit(2);

                }
                if (bind(s, (struct sockaddr *)pingfrom->ai_addr, sizeof(struct sockaddr_storage)) == -1) {
                        if (options & O_IPV6)
                                inet_ntop(&((struct sockaddr_in6 *)pingfrom->ai_addr)->sin6_addr);
                        else
                                inet_ntop(&((struct sockaddr_in *)pingfrom->ai_addr)->sin_addr);

                        fprintf(stderr, "unable to set source address %s\n", address);
                        exit(2);
                }
                freeaddrinfo(pingfrom);
        }

        memset(&stats, 0, sizeof(stats));
        

#ifdef __linux__
        setuid(getuid());
#endif
        
        signal(SIGINT, finish);
        
        if (options & O_LOOP)
                nrepeat = 1;
        if (options & O_IVAL)
                signal(SIGALRM, sendping);
        
        fprintf(stdout, "Type escape sequence to abort.\n");
       
        if (options & O_IPV6)
                inet_ntop(&((struct sockaddr_in6 *)to)->sin6_addr);
        else
                inet_ntop(&((struct sockaddr_in *)to)->sin_addr);
        
        if (options & O_LOOP) {
                fprintf(stdout, "Sending %d-byte ICMP Echos to %s, \nevery %d-second interval, timeout is %d seconds:\n\n",
                        datalen, address, interval, timeout);
        } else {
                fprintf(stdout, "Sending %d, %d-byte ICMP Echos to %s, timeout is %d seconds:\n",
                        nrepeat, datalen, address, timeout);
        }

        fflush(stdout);
        
        for (i = 0; i<nrepeat; i++) {
                if (!(i & 0xFFFF))
                        sendping(0);
                else if (!(options & O_IVAL))
                        sendping(0);

                for (;;) {
                        sz = recvfrom(s, (char *)rcv_pkt, plen, 0,
                                (struct sockaddr *)&src, (socklen_t *)&addrlen);
                                
                                if (options & O_IPV6) {
                                        if (pr6((char *)rcv_pkt, sz))
                                                if (!(options & O_LOOP))
                                                        break;
                                } else {
                                        if (pr((char *)rcv_pkt, sz))
                                                if (!(options & O_LOOP))
                                                        break;
                                }
                }
        }
        
        finish(0);
        exit(1);
}


/*
 * Routine ini untuk mengirim paket icmp. Berbeda dengan versi original,
 * sendping() dalam mode interval tidak akan mengirim paket jika paket
 * icmp sebelumnya tidak diterima atau belum mencapai waktu timeout.
 */
static void sendping(int blah)
{
        (void)blah;
        struct icmphdr *icmph;
        struct iphdr *iph;
        struct addrinfo *p, *res, hint;

        struct timeval *tv;
        int sz, i;

        if (options & O_IVAL)
                alarm((u_int)interval);

        if (S_TRANSMIT > 0)
                if (!(TST(S_TRANSMIT % (MAXTRACK * 8))))
                        return;

        iph = (struct iphdr *)snd_pkt;
        iph->ihl = 5;
        icmph = (struct icmphdr *)snd_pkt;

        if (options & O_IPV6) {
                ((struct icmp6hdr *)icmph)->icmp6_type = ICMP_TYPE;
                ((struct icmp6hdr *)icmph)->icmp6_code = 0;
                ((struct icmp6hdr *)icmph)->icmp6_cksum = 0;
                ((struct icmp6hdr *)icmph)->icmp6_sequence = htons(++S_TRANSMIT);
                ((struct icmp6hdr *)icmph)->icmp6_identifier = id;
        } else {
                icmph->type = ICMP_TYPE;
                icmph->code = 0;
                icmph->checksum  = 0;
                icmph->un.echo.sequence = htons(++S_TRANSMIT);
                icmph->un.echo.id = id;
        }

        tv = (struct timeval *)&snd_pkt[8];
        (void)gettimeofday(tv, (struct timezone *)NULL);

        sz = datalen + 8;
        if (!(options & O_IPV6))
                icmph->checksum = in_cksum((u_short *)icmph, sz);
      
        CLR(S_TRANSMIT % (MAXTRACK * 8));

        i = sendto(s, (char *)snd_pkt, sz, 0, (struct sockaddr *)&dst, sizeof(struct sockaddr_storage));
        if (i < 0) {
                fprintf(stderr, "error sendping.\n");
                exit(2);
        }
}

/*
 * int pr (char *buf, int psize)
 * print icmp ipv4 packet
 * char *buf: pointer ke buffer paket yg diterima
 * int psize: besar packet yang diterima + icmp header
 * dua routine untuk print packet icmp dan icmpv6 karena satu
 * routine terlalu campur aduk.
 * Ugly? yes I know.
 * return value: 1 success, 0 !success
 */
int pr(char *buf, int psize)
{
        struct timeval tvin, *tvout = NULL;
        struct icmphdr *icmph;

        struct iphdr *iph;
        int hlen, seq;

        iph = (struct iphdr *)buf;
        hlen = iph->ihl << 2;
        psize -= (hlen + 8);
        icmph = (struct icmphdr *)(buf + hlen);
        tvout = (struct timeval *)(buf + hlen + 8);
        seq = ntohs(icmph->un.echo.sequence);

        do {
                if (icmph->type == ICMP_ECHOREPLY && 
                                ((int)icmph->un.echo.id) == id) {
                                
                        if (TST(ntohs(icmph->un.echo.sequence) % (MAXTRACK * 8)))
                                break;
        
                        SET(ntohs(icmph->un.echo.sequence) % (MAXTRACK * 8));
                        
                        (void)gettimeofday(&tvin, (struct timezone *)NULL);
                        S_RCVD++;
        
                        int ms = (((tvin.tv_sec - tvout->tv_sec) * 1000000) + 
                                (tvin.tv_usec - tvout->tv_usec)) / 
                                1000;
                
                        if (options & O_BRIEF) {
                                inet_ntop(&((struct sockaddr_in *)&dst)->sin_addr);
                                fprintf(stdout, "Reply from %s: size=%d bytes seq=%d rtt=%d ms\n",
                                                address,
                                                psize, 
                                                seq,
                                                ms
                                );
                        } else write(STDOUT_FILENO, &REPLY, 1);
        
        
                        if (ms < S_MIN || !(S_MIN & 0xFF))
                                S_MIN = ms;
                        if (ms > S_MAX)
                                S_MAX = ms;
                        
                        if (!(S_AVG & 0xFF))
                                S_AVG = ms;
                        else
                                S_AVG = (S_AVG + ms) / 2;

                        return 1;
                }
        } while(0);

        icmph = (struct icmphdr *)&snd_pkt;
        tvout = (struct timeval *)&snd_pkt[8];

        gettimeofday(&tvin, (struct timezone *)NULL);
        
        if (TST(ntohs(icmph->un.echo.sequence) % (MAXTRACK * 8)))
                return 0;
        
        if ((tvin.tv_sec - tvout->tv_sec) >= timeout) {
                if (!(options & O_BRIEF))
                        write(STDOUT_FILENO, &TIMEOUT, 1);
                else
                        fprintf(stdout, "Ping #%d timeout...\n", ntohs(icmph->un.echo.sequence));
                
                SET(ntohs(icmph->un.echo.sequence) % (MAXTRACK * 8));
                
                return 1;
        }
        
        return 0;
}


/*
 * int pr6 (char *buf, int psize)
 * print icmpv6 packet
 * char *buf: pointer ke buffer paket yg diterima
 * int psize: besar packet yang diterima + icmp header
 * dua routine untuk print packet icmp dan icmpv6 karena satu
 * routine terlalu campur aduk.
 * Ugly? yes I know.
 * Berbeda dengan icmp ipv4, char *buf untuk icmpv6 tidak ada header ipv6
 */
int pr6(char *buf, int psize)
{
        struct timeval tvin, *tvout = NULL;
        struct icmp6hdr *icmp6h;

        int seq;

        icmp6h = (struct icmp6hdr *)buf;
        tvout = (struct timeval *)(buf + 8);
        seq = ntohs(icmp6h->icmp6_sequence);
        psize -= 8;

        do {
                if (icmp6h->icmp6_type == ICMPV6_ECHO_REPLY &&
                        ((int)icmp6h->icmp6_identifier) == id) {
                
                        if (TST(ntohs(icmp6h->icmp6_sequence) % (MAXTRACK *8)))
                                break;
                        SET(ntohs(icmp6h->icmp6_sequence) % (MAXTRACK * 8));
                        (void)gettimeofday(&tvin, (struct timezone *)NULL);
                        S_RCVD++;
        
                        int ms = (((tvin.tv_sec - tvout->tv_sec) * 1000000) + 
                                (tvin.tv_usec - tvout->tv_usec)) / 
                                1000;
                
                        if (options & O_BRIEF) {
                                inet_ntop(&((struct sockaddr_in6 *)&dst)->sin6_addr);
                                fprintf(stdout, "Reply from %s: size=%d bytes seq=%d rtt=%d ms\n",
                                                address,
                                                psize, 
                                                seq,
                                                ms
                                );
                        } else write(STDOUT_FILENO, &REPLY, 1);
        
        
                        if (ms < S_MIN || !(S_MIN & 0xFF))
                                S_MIN = ms;
                        if (ms > S_MAX)
                                S_MAX = ms;
                        
                        if (!(S_AVG & 0xFF))
                                S_AVG = ms;
                        else
                                S_AVG = (S_AVG + ms) / 2;
        
        
                        return 1;
                }
        } while(0);
                
        icmp6h = (struct icmp6hdr *)&snd_pkt;
        tvout = (struct timeval *)&snd_pkt[8];
        
        gettimeofday(&tvin, (struct timezone *)NULL);
        
        if (TST(ntohs(icmp6h->icmp6_sequence) % (MAXTRACK * 8)))
                return 0;
        
        if ((tvin.tv_sec - tvout->tv_sec) >= timeout) {
                if (!(options & O_BRIEF))
                        write(STDOUT_FILENO, &TIMEOUT, 1);
                else
                        fprintf(stdout, "Ping #%d timeout...\n", ntohs(icmp6h->icmp6_sequence));
                
                SET(ntohs(icmp6h->icmp6_sequence) % (MAXTRACK * 8));
                
                return 1;
        }
        
        return 0;
}


/*
 * finish(): Print statistik ping, dipanggil dengan signal(SIGINT, finish)
 * atau akhir loop.
 */
static void finish(int blah)
{
        free(rcv_pkt);
        free(address);
        putchar('\n');

        S_PERCENT = S_RCVD * 100 / S_TRANSMIT;
        fprintf(stdout, "Success rate is %d percent (%d/%d)",
                        S_PERCENT, S_RCVD, S_TRANSMIT);

        if (S_RCVD > 0)
                fprintf(stdout, ", round-trip min/avg/max = %d/%d/%d ms",
                                S_MIN, S_AVG, S_MAX);

        putchar('\n');
        fflush(stdout);
        exit(0);
}

/*
 * Diambil dari routine ping original, untuk kalkulasi icmp header checksum.
 * Tidak diperlukan untuk ipv6
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
static int
in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

void usage(void)
{
        fprintf(stdout, "Description:\n");
        fprintf(stdout, "   Send and receive icmp or icmpv6 packet, and print packet round-trip time\n");
        fprintf(stdout, "Options:\n");
        fprintf(stdout, "   destination                 Destination address or hostname\n");
        fprintf(stdout, "   ipv6                        Force ping to use ipv6 address\n");
        fprintf(stdout, "   ipv4                        Force ping to use ipv4 address\n");
        fprintf(stdout, "   repeat <n>                  Repeat ping for n times\n");
        fprintf(stdout, "   source <src addr>           Ping from source address\n");
        fprintf(stdout, "   interval <n>                Ping every n-second interval\n");
        fprintf(stdout, "   size <n>                    Send ping with n bytes icmp data size\n");
        fprintf(stdout, "   timeout <n>                 Timeout value in second\n");
        fprintf(stdout, "   forever                     Infinite loop ping\n");
        fprintf(stdout, "   verbose                     Print ping details\n");
}
