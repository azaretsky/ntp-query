#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define NTP_EPOCH 2208988800

static
void put_be64(uint64_t i, uint8_t *o)
{
    o[0] = (i >> 56) & 0xff;
    o[1] = (i >> 48) & 0xff;
    o[2] = (i >> 40) & 0xff;
    o[3] = (i >> 32) & 0xff;
    o[4] = (i >> 24) & 0xff;
    o[5] = (i >> 16) & 0xff;
    o[6] = (i >> 8) & 0xff;
    o[7] = i & 0xff;
}

static
uint32_t get_be32(const uint8_t *i)
{
    return (i[0] << 24) | (i[1] << 16) | (i[2] << 8) | i[3];
}

static
uint64_t get_be64(const uint8_t *i)
{
    return ((uint64_t) get_be32(i)) << 32 | get_be32(i + 4);
}

static
double ntp_to_unix(uint64_t ntp_ts)
{
    return ldexp(ntp_ts, -32) - NTP_EPOCH;
}

static
double get_short_ts_ms(const uint8_t *i)
{
    return ldexp(get_be32(i), -16) * 1000;
}

static
uint64_t ntp_gettimeofday(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (((uint64_t) tv.tv_sec) + NTP_EPOCH) << 32 | ((((uint64_t) tv.tv_usec) << 32) / 1000000);
}

static
void sntp_query(const struct addrinfo *ai)
{
    uint8_t packet[48] = {0};
    uint64_t org, ref, server_org, rcv, xmt, dst;
    int s;
    s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == -1) {
        perror("socket");
        return;
    }
    /*
    3 << 6 - leap indicator (unknown (clock unsynchronized))
    4 << 3 - version number (NTPv4)
    3 - mode 3 (client)
    */
    packet[0] = (3 << 6) | (4 << 3) | 3;
    /* stratum 16 - unsynchronized */
    packet[1] = 16;
    org = ntp_gettimeofday();
    put_be64(org, packet + 40);
    if (sendto(s, packet, sizeof(packet), 0, ai->ai_addr, ai->ai_addrlen) == -1) {
        perror("sendto");
        close(s);
        return;
    }
    if (read(s, packet, sizeof(packet)) < (ssize_t) sizeof(packet)) {
        if (errno == EINTR)
            fprintf(stderr, "skipping\n");
        else
            perror("read");
        close(s);
        return;
    }
    dst = ntp_gettimeofday();
    close(s);
    printf(
        "li = %d\nvn = %d\nmode = %d\n"
        "stratum = %d\npoll = %d\nprecision = %d\n"
        "root delay = %.3f\nroot dispersion = %.3f\n",
        (packet[0] >> 6) & 3, (packet[0] >> 3) & 7, packet[0] & 7,
        packet[1], packet[2], (int8_t) packet[3],
        get_short_ts_ms(packet + 4), get_short_ts_ms(packet + 8)
    );
    printf("refid = ");
    if (packet[1] == 0 || packet[1] == 1) {
        char refid[5];
        memcpy(refid, packet + 12, 4);
        refid[4] = '\0';
        printf("%s:%s", packet[1] == 0 ? "kod" : "clock", refid);
    } else if (ai->ai_family == AF_INET) {
        char refid[INET_ADDRSTRLEN];
        struct in_addr addr;
        memcpy(&addr.s_addr, packet + 12, 4);
        inet_ntop(AF_INET, &addr, refid, sizeof(refid));
        printf("%s", refid);
    } else
        printf("0x%08x", get_be32(packet + 12));
    printf("\n");
    ref = get_be64(packet + 16);
    server_org = get_be64(packet + 24);
    rcv = get_be64(packet + 32);
    xmt = get_be64(packet + 40);
    if (org != server_org)
        fprintf(stderr, "our org is %llu but the server replied with %llu\n", org, server_org);
    printf("ref = %f\norg = %f\nrcv = %f\nxmt = %f\ndst = %f\n",
        ntp_to_unix(ref),
        ntp_to_unix(org),
        ntp_to_unix(rcv),
        ntp_to_unix(xmt),
        ntp_to_unix(dst)
    );
    printf(
        "offset (theta) = %f\ndelay (delta) = %f\n",
        ldexp((int64_t) ((rcv - org) - (dst - xmt)), -33),
        ldexp((int64_t) ((dst - org) - (xmt - rcv)), -32)
    );
}

static
void dummy_signal_handler(int signum)
{
}

static
int make_SIGINT_generate_EINTR(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = dummy_signal_handler;
    if (sigaction(SIGINT, &sa, NULL) != 0) {
        perror("sigaction(SIGINT)");
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    const char *hostspec, *portspec;
    const struct addrinfo *ai;
    struct addrinfo *addrs, hints = {
        .ai_flags = AI_V4MAPPED | AI_ADDRCONFIG,
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = 0,
        .ai_addrlen = 0,
        .ai_addr = NULL,
        .ai_canonname = NULL,
        .ai_next = NULL
    };
    int err;
    if (argc < 2) {
        fprintf(stderr, "Usage: sntp-query host [port|service]\n");
        return 1;
    }
    hostspec = argv[1];
    portspec = argc < 3 ? "ntp" : argv[2];
    err = getaddrinfo(hostspec, portspec, &hints, &addrs);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo: %s (%d)\n", gai_strerror(err), err);
        return 1;
    }
    if (!make_SIGINT_generate_EINTR()) {
        freeaddrinfo(addrs);
        return 1;
    }
    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        char hostbuf[NI_MAXHOST], servbuf[NI_MAXSERV];
        err = getnameinfo(ai->ai_addr, ai->ai_addrlen, hostbuf, sizeof(hostbuf), servbuf, sizeof(servbuf), NI_DGRAM | NI_NUMERICHOST | NI_NUMERICSERV);
        if (err != 0)
            fprintf(stderr, "getnameinfo: %s (%d)\n", gai_strerror(err), err);
        else
            printf("%s %s\n", hostbuf, servbuf);
        sntp_query(ai);
        if (ai->ai_next != NULL)
            printf("\n");
    }
    freeaddrinfo(addrs);
    return 0;
}
