/*
 * router.c
 * Router tool for detecting attacks
 *
 * @author : Himanshu Mehra
 * @email  : hmehra@usc.edu
 * @project: ISI Project
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/icmp.h>
#include <search.h>
#include <unistd.h>
#include "router.h"


/* Global variable */
static router_input_t  input;
static int             trback_sockfd;

#define ROUTER_GET_PKT_TIME(_h_)      \
    ((_h_)->ts.tv_sec + (double)(_h_)->ts.tv_usec/1000000)


static struct option
long_options[] = {
    {"help"       , no_argument      , 0, 'h'},
    {"epoch"      , required_argument, 0, 'e'},
    {"probability", required_argument, 0, 'p'},
    {"tcp-port"   , required_argument, 0, 't'},
    {"udp-port"   , required_argument, 0, 'u'},
    {0, 0, 0, 0}
};


static const char *
options_help[] = {
    "Display this help and exit",
    "Time epoch for logging",
    "Probablity to generate traceback message",
    "TCP port to listen and receive control signals",
    "UDP port to send traceback messages",
    NULL,
};



static void
router_print_usage (char *progname)
{
    int i = 0;

    printf("\nUsage:\n router OPTIONS\n\n");
    while (long_options[i].name) {
        printf(" -%c, --%-13s %s\n",
                long_options[i].val,
                long_options[i].name,
                options_help[i]);
        i++;
    }
    printf("\n");
    return;
}


static inline void
router_read_input (router_input_t   *input,
                   char            **argv,
                   int               argc)
{
    int    opt_idx = 0;
    int    opt;

    for (;;) {
        opt = getopt_long(argc, argv, "he:t:p:u:",
                          long_options, &opt_idx);

        if (opt == -1) {
            break;  /* End of input */
        }

        switch (opt) {
        case 'e':
            input->epoch = atoi(optarg);
            break;
        case 't':
            input->tcp_port = atoi(optarg);
            break;
        case 'u':
            input->udp_port = atoi(optarg);
            break;
        case 'p':
            input->probability = atof(optarg);
            break;
        case 'h':
            router_print_usage(argv[0]);
            exit(0);
        case '?':
            break;
        default:
            abort();
        }
    }

    if ((input->tcp_port == 0) ||
        (input->udp_port == 0) ||
        (input->epoch == 0)) {
        printf("Please speicify all options\n");
        router_print_usage(argv[0]);
        exit(0);
    }

    if ((input->tcp_port > UINT16_MAX) ||
        (input->udp_port > UINT16_MAX)) {
        printf("Please input valid port numbers (< 65535)\n");
        router_print_usage(argv[0]);
        exit(0);
    }

    return;
}


static inline void
router_send_traceback_message (uint32_t   victim_addr,
                               uint16_t   victim_port,
                               uint8_t    forward,
                               uint8_t   *buf,
                               uint16_t   buflen,
                               uint8_t    num_ips)
{
    struct sockaddr_in    srvaddr;
    struct in_addr        addr;
    static uint8_t        started = TRUE;
    DEBUG_VAR(char,       str2[INET_ADDRSTRLEN]);
    char                  str[INET_ADDRSTRLEN];
    int                   rc;


    /* Fill server details */
    memset(&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sin_family      = AF_INET;
    srvaddr.sin_port        = htons(victim_port);
    srvaddr.sin_addr.s_addr = htonl(victim_addr);

    rc = sendto(trback_sockfd, buf, buflen, 0,
                (struct sockaddr *)&srvaddr,
                sizeof(struct sockaddr_in));
    if (rc < 0) {
        printf("Error sending traceback msg to %s. Reason: %s\n",
               inet_ntop(AF_INET, &srvaddr.sin_addr,
                         str, sizeof(str)),
               strerror(errno));
        return;
    }

    addr.s_addr = htonl(input.local_addr);
    (void)addr;

    DEBUG_LOG("Traceback [%c / %u] [%s => %s]\n",
              (forward ? 'F' : 'I'), num_ips,
              inet_ntop(AF_INET, &srvaddr.sin_addr,
                        str, sizeof(str)),
              inet_ntop(AF_INET, &addr,
                        str2, sizeof(str2)));

    if (!forward && started) {
        started = FALSE;
        fprintf(input.loghdl,
                "%.6f  startedMarking  %s\n",
                __time(), "Traceback message");
    }

    return;
}


static inline void
router_intercept_traceback_msg (const uint8_t  *data,
                                uint16_t        data_len,
                                uint32_t        router_addr,
                                uint32_t        victim_addr,
                                uint16_t        victim_port)
{
    uint8_t    buf[MAX_BUF_LEN] = {0};
    uint8_t    num_ips, len;

    /*
     * +---------------------------+
     * |    MAGIC - 0xDEADBEEF     |  4 bytes
     * +---------------------------+
     * |       MSGTYPE_PATH        |  1 byte
     * +---------------------------+
     * |    Number of IPs (n)      |  1 byte
     * +---------------------------+
     * |       Attacker IP         |  4 byte
     * +---------------------------+
     * /       Router IP # 1       /
     * /       Router IP # 2       /  (n-1) * 4 bytes
     * .............................
     */

    /* Check for our magic */
    if (GET_UINT32(data) != TRACEBACK_MAGIC) {
        printf("Ignoring non-traceback msg on traceback port\n");
        return;
    }

    /* Sanity check */
    num_ips = data[TRACEBACK_MAGIC_SZ + 1];
    assert(num_ips < MAX_ROUTERS);

    if (data_len < TRACEBACK_MSG_LEN(num_ips)) {
        printf("Rcvd shorter datagram of %u bytes. Expected %u bytes\n",
               data_len, TRACEBACK_MSG_LEN(num_ips));
        return;
    }

    /* Create a copy of the message */
    len = TRACEBACK_MSG_LEN(num_ips);
    memcpy(buf, data, len);

    /* Update the message type */
    buf[TRACEBACK_MAGIC_SZ] = TRACEBACK_MSGTYPE_PATH;

    /* Now append our address */
    ++num_ips;
    buf[TRACEBACK_MAGIC_SZ + 1] = num_ips;
    PUT_UINT32(&buf[len], router_addr);

    /* Forward traceback message */
    router_send_traceback_message(victim_addr,
                                  victim_port,
                                  TRUE, buf,
                                  TRACEBACK_MSG_LEN(num_ips),
                                  num_ips);
    return;
}


static void
router_process_filtered_pkt (uint8_t                   *user,
                             const struct pcap_pkthdr  *hdr,
                             const uint8_t             *bytes)
{
    struct ether_header  *ether;
    router_pcap_loop_t   *rinp  = (router_pcap_loop_t *)user;
    struct in_addr        addr;
    static uint8_t        first = TRUE;
    uint8_t               buf[MAX_BUF_LEN] = {0};
    char                  str[INET_ADDRSTRLEN];
    struct iphdr         *ip;
    struct udphdr        *udp;
    uint8_t              *payload, idx;
    uint16_t              payload_len;
    double                curr_time;

    /*
     * FOR SOME REASON, THE ETHERNET HEADER STARTS AT
     * SECOND BYTE WHEN CAPTURING PACKETS ON "ANY"
     * DEVICE. ACCOUNT FOR THIS
     */
    bytes += 2;

    ether   = (struct ether_header *)(bytes);
    ip      = (struct iphdr *)(ether + 1);
    udp     = (struct udphdr *)(ip + 1);
    payload = (uint8_t *)(udp + 1);

    assert(ether->ether_type == htons(ETHERTYPE_IP));

    /* Safety check */
    if (ip->saddr == htonl(rinp->router_addr)) {
        return;
    }

    /* Check for END signal from victim */
    if (ip->saddr == htonl(rinp->victim_addr)) {
        if ((ip->protocol == IPPROTO_UDP)           &&
            (ip->daddr == htonl(rinp->router_addr)) &&
            (udp->dest == htons(input.tcp_port))) {

            curr_time = ROUTER_GET_PKT_TIME(hdr);
            if (input.epoch_cnt) {
                addr.s_addr = htonl(rinp->victim_addr);
                fprintf(input.loghdl,
                        "%.6f  %-15s  %u\n",
                        input.epoch_start,
                        inet_ntop(AF_INET, &addr, str, sizeof(str)),
                        input.epoch_cnt);
            }
            close(trback_sockfd);
            fflush(input.loghdl);
            fclose(input.loghdl);
            exit(0);
        }
        return;
    }

    assert(ip->daddr == htonl(rinp->victim_addr));
    payload_len = hdr->len - (payload - bytes);

    /*
     * If traceback message, append our IP address
     * to the list of IPs in buffer
     */
    if ((ip->protocol == IPPROTO_UDP) &&
        (udp->dest == htons(rinp->victim_port))) {
        router_intercept_traceback_msg(payload,
                                       payload_len,
                                       rinp->router_addr,
                                       rinp->victim_addr,
                                       rinp->victim_port);
        return;
    }

    /* Check if we can send packets */
    if (RANDOM() > input.probability) {
        return;
    }

    /*
     * Prepare traceback message
     *
     * +---------------------------+
     * |    MAGIC - 0xDEADBEEF     |  4 bytes
     * +---------------------------+
     * |       MSGTYPE_ATTACK      |  1 byte
     * +---------------------------+
     * |    Number of IPs (n)      |  1 byte
     * +---------------------------+
     * |       Attacker IP         |  4 byte
     * +---------------------------+
     * /       Router IP # 1       /
     * /       Router IP # 2       /  (n-1) * 4 bytes
     * .............................
     */
    idx = 0;
    PUT_UINT32(&buf[idx], TRACEBACK_MAGIC);
    idx += TRACEBACK_MAGIC_SZ;

    buf[idx++] = TRACEBACK_MSGTYPE_ATTACK;
    buf[idx++] = 2;   /* Attacker + Victim */

    /* Attacker address */
    PUT_UINT32(&buf[idx], ntohl(ip->saddr));
    idx += sizeof(uint32_t);

    /* Router address */
    PUT_UINT32(&buf[idx], rinp->router_addr);
    idx += sizeof(uint32_t);

    assert(idx == TRACEBACK_MSG_LEN(2));
    router_send_traceback_message(rinp->victim_addr,
                                  rinp->victim_port,
                                  FALSE, buf,
                                  TRACEBACK_MSG_LEN(2),
                                  2);
    input.epoch_cnt++;

    /* Log epoch count */
    curr_time = ROUTER_GET_PKT_TIME(hdr);
    if (first) {
        first = FALSE;
        input.epoch_start = curr_time;

    } else if ((curr_time - input.epoch_start) > input.epoch) {
        struct in_addr  addr;
        uint16_t        num_epochs;
        char            str[INET_ADDRSTRLEN];

        addr.s_addr = htonl(rinp->victim_addr);
        num_epochs = (curr_time - input.epoch_start) / input.epoch;

        for (idx=0; idx < num_epochs; idx++) {
            fprintf(input.loghdl,
                    "%.6f  %-15s  %u\n",
                    input.epoch_start,
                    inet_ntop(AF_INET, &addr, str, sizeof(str)),
                    input.epoch_cnt);

            input.epoch_start += input.epoch;
            input.epoch_cnt = 0;
        }
    }
    return;
}


const char *
router_get_devname (uint32_t  router_addr)
{
    pcap_if_t           *alldevs;
    pcap_if_t           *d;
    struct in_addr       addr;
    DEBUG_VAR(char,      buf[INET_ADDRSTRLEN]);
    char                 errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error in pcap_findalldevs: %s\n", errbuf);
        return NULL;
    }

    for (d=alldevs; d != NULL; d=d->next) {
        struct pcap_addr    *paddr = d->addresses;
        struct sockaddr_in  *iaddr;

        while (paddr != NULL) {
            iaddr = (struct sockaddr_in *)paddr->addr;
            if ((iaddr != NULL) &&
                (iaddr->sin_addr.s_addr == htonl(router_addr))) {

                DEBUG_LOG("Found device %s w/ address: %s\n",
                          d->name,
                          inet_ntop(AF_INET, &iaddr->sin_addr,
                                    buf, sizeof(buf)));
                return d->name;
            }
            paddr = paddr->next;
        }
    }

    addr.s_addr = htonl(router_addr);
    (void)addr;
    DEBUG_LOG("Could not find device for address: %s\n",
              inet_ntop(AF_INET, &addr, buf, sizeof(buf)));

    return NULL;
}



static inline void
router_start_scanning_packets (uint32_t  router_addr,
                               uint32_t  victim_addr,
                               uint16_t  victim_port)
{
    struct bpf_program       fp;
    router_pcap_loop_t       rinp;
    struct in_addr           addr;
    pcap_t                  *pcap_hdl;
    const char              *devname;
    char                     errbuf[PCAP_ERRBUF_SIZE];
    char                     filter[MAX_BUF_LEN] = {0};
    char                     buf[INET_ADDRSTRLEN];
    int                      ret;

    /* Get device to sniff on */
    devname = router_get_devname(router_addr);
    if (devname == NULL) {
        exit(0);
    }

    /* Open pcap file */
    pcap_hdl = pcap_open_live("any", MAX_BUF_LEN, 0, -1, errbuf);
    if (pcap_hdl == NULL) {
        printf("%s\n", errbuf);
        return;
    }

    /* Only interested in incoming packets */
    ret = pcap_setdirection(pcap_hdl, PCAP_D_IN);
    assert(ret == 0);

    /* Compie and set filter for victim IP */
    addr.s_addr = htonl(victim_addr);
    snprintf(filter, MAX_BUF_LEN, "ip host %s",
             inet_ntop(AF_INET, &addr, buf, sizeof(buf)));

    ret = pcap_compile(pcap_hdl, &fp, filter, 0, 0);
    assert(ret == 0);

    ret = pcap_setfilter(pcap_hdl, &fp);
    assert(ret == 0);

    /* Sniff Sniff! */
    rinp.victim_addr = victim_addr;
    rinp.victim_port = victim_port;
    rinp.router_addr = router_addr;
    pcap_loop(pcap_hdl, -1, router_process_filtered_pkt,
              (uint8_t *)&rinp);

    return;
}


static int
router_wait_for_notifications (uint16_t port)
{
    struct sockaddr_in  lcladdr;
    struct sockaddr_in  cliaddr;
    DEBUG_VAR(char,     str2[INET_ADDRSTRLEN]);
    int                 cli_sockfd;
    int                 sockfd, rc, yes=1;
    char                str[INET_ADDRSTRLEN];
    char                msg[MAX_BUF_LEN];

    /* Create socket for service */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){
        perror("Error creating socket. Reason");
        return sockfd;
    }

    /* Set socket options */
    rc = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
                    &yes, sizeof(int));
    if (rc < 0){
        perror("Error setting socket options. Reason");
        return rc;
    }

    /* Fill bind details */
    memset(&lcladdr, 0, sizeof(lcladdr));
    lcladdr.sin_family      = AF_INET;
    lcladdr.sin_port        = htons(port);
    lcladdr.sin_addr.s_addr = htonl(INADDR_ANY);

    /* Bind to local addr-port */
    rc = bind(sockfd, (struct sockaddr *)&lcladdr,
              sizeof(struct sockaddr));
    if (rc < 0){
        perror("Error binding addr-port. Reason");
        return rc;
    }

    /* Set backlog queue length */
    rc = listen(sockfd, 10);
    if (rc < 0) {
        perror("Error setting backlog. Reason");
        return rc;
    }

    /* Wait for TCP connections */
    for (;;) {
        socklen_t   len = sizeof(struct sockaddr_in);
        cli_sockfd = accept(sockfd, (struct sockaddr *)&cliaddr, &len);
        if (cli_sockfd < 0) {
            perror("Error accepting connection. Reason");
            break;
        }

        /* Read from client socket */
        rc = read(cli_sockfd, msg, sizeof(msg));
        if (rc < 0) {
            perror("Error reading from client socket. Reason");
            return rc;
        }
        msg[rc] = '\0'; /* Truncate message */

        /* Fetch local addr/port from kernel */
        len = sizeof(struct sockaddr_in);
        rc = getsockname(cli_sockfd, (struct sockaddr *)&lcladdr, &len);
        if (rc < 0) {
            perror("Error fetching socket name. Reason");
            return rc;
        }
        close(cli_sockfd);
        break;
    }

    DEBUG_LOG("Control signal  [%s => %s]\n",
              inet_ntop(AF_INET, &cliaddr.sin_addr,
                        str, sizeof(str)),
              inet_ntop(AF_INET, &lcladdr.sin_addr,
                        str2, sizeof(str2)));

    /* Log got-marking */
    fprintf(input.loghdl,
            "%.6f  gotMarking  %s %s\n",
            __time(), inet_ntop(AF_INET, &cliaddr.sin_addr,
                                str, sizeof(str)), msg);

    /*
     * Bind traceback socket to the address on
     * which control signal was received. This
     * same address is supposed to be used while
     * sending traceback messages
     */
    lcladdr.sin_port = ntohs(0);
    input.local_addr = ntohl(lcladdr.sin_addr.s_addr);
    rc = bind(trback_sockfd, (struct sockaddr *)&lcladdr,
              sizeof(struct sockaddr_in));
    if (rc < 0) {
        perror("Error binding traceback socket. Reason");
        return rc;
    }

    /* DDOS detected. Start scanning packets */
    router_start_scanning_packets(ntohl(lcladdr.sin_addr.s_addr),
                                  ntohl(cliaddr.sin_addr.s_addr),
                                  input.udp_port);
    return 0;
}


static inline void
router_create_logfile (router_input_t  *input)
{
    char  hostname[MAX_BUF_LEN];
    char  filename[MAX_BUF_LEN+16];
    int   ret;

    /* Store hostname upfront */
    ret = gethostname(hostname, MAX_BUF_LEN);
    assert(ret == 0);

    snprintf(filename, MAX_BUF_LEN+16,
             "%s.router.log", hostname);

    input->loghdl = fopen(filename, "w+");
    if (input->loghdl == NULL) {
        perror("Error creating output file. Reason");
        exit(0);
    }

    return;
}


static inline void
router_setup_traceback_socket (void)
{
    int ttl = DEFAULT_TTL;
    int rc;

    /* Create socket */
    trback_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (trback_sockfd < 0){
        perror("Error creating socket. Reason");
        exit(trback_sockfd);
    }

    /* Set socket options */
    rc = setsockopt(trback_sockfd, IPPROTO_IP, IP_TTL,
                    &ttl, sizeof(int));
    if (rc < 0){
        perror("Error setting socket option. Reason");
        exit(rc);
    }

    return;
}


int
main (int   argc,
      char *argv[])
{
    /* Read input */
    bzero(&input, sizeof(input));

    /* Read input */
    router_read_input(&input, argv, argc);

    /* Create logfile */
    router_create_logfile(&input);

    /* Setup traceback socket */
    router_setup_traceback_socket();

    /* Wait for notifications from endhost */
    router_wait_for_notifications(input.tcp_port);

    fflush(input.loghdl);
    fclose(input.loghdl);
    close(trback_sockfd);
    return 0;
}
