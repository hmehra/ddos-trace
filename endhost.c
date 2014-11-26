/*
 * endhost.c
 * Endhost tool for detecting attacks
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
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/icmp.h>
#include <search.h>
#include <unistd.h>
#include "endhost.h"
#include "router.h"


/* Global variable */
static endhost_input_t   input;
static uint32_t          self_addr = 0;
static void             *attacker_tree = NULL;

static struct option
long_options[] = {
    {"help"      , no_argument      , 0, 'h'},
    {"filename"  , required_argument, 0, 'r'},
    {"stopthresh", required_argument, 0, 's'},
    {"tcp-port"  , required_argument, 0, 't'},
    {"udp-port"  , required_argument, 0, 'u'},
    {0, 0, 0, 0}
};


static const char *
options_help[] = {
    "Display this help and exit",
    "Router list file",
    "Threshold to terminate path reconstrucion",
    "TCP port to send control signals",
    "UDP port to receive traceback messages",
    NULL,
};



static void
endhost_print_usage (char *progname)
{
    int i = 0;

    printf("\nUsage:\n endhost OPTIONS\n\n");
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


static int
endhost_read_router_file (endhost_input_t *input)
{
    FILE    *fp;
    char     line[MAX_BUF_LEN] = {0};
    int      rc, idx=0;

    /* Init handle */
    fp = fopen(input->router_file, "r");
    if (fp == NULL) {
        perror("Error opening router file. Reason");
        return -1;
    }

    while (fgets(line, MAX_BUF_LEN, fp) != NULL) {
        input->num_routers++;
    }

    if (input->num_routers == 0) {
        printf("No routers specified in router file\n");
        return -1;
    }

    input->routers = calloc(input->num_routers,
                            sizeof(endhost_router_t));
    if (input->routers == NULL) {
        perror("Error allocating memory. Reason");
        return -1;
    }

    /* Rewind to the start */
    rewind(fp);
    while (fgets(line, MAX_BUF_LEN, fp) != NULL) {
        struct in_addr  addr;
        uint8_t         len = strlen(line);

        line[len-1] = 0;  /* Strip '\n' */
        rc = inet_pton(AF_INET, line, &addr);
        if (rc <= 0) {
            if (rc == 0) {
                printf("%s not in presentation format\n", line);
            } else {
                perror("Error parsing router address. Reason");
            }
            fclose(fp);
            return -1;
        }

        input->routers[idx++].router_addr = addr.s_addr;
        DEBUG_LOG("Router: %-15s (0x%08x)\n", line,
                  ntohl(addr.s_addr));
    }

    fclose(fp);
    return 0;
}


static inline void
endhost_read_input (endhost_input_t   *input,
                    char             **argv,
                    int                argc)
{
    int    opt_idx = 0;
    int    opt;

    for (;;) {
        opt = getopt_long(argc, argv, "hr:s:t:u:",
                          long_options, &opt_idx);

        if (opt == -1) {
            break;  /* End of input */
        }

        switch (opt) {
        case 'r':
            strncpy(input->router_file, optarg, MAX_NAME_LEN);
            break;
        case 's':
            input->stop_threshold = atoi(optarg);
            break;
        case 't':
            input->tcp_port = atoi(optarg);
            break;
        case 'u':
            input->udp_port = atoi(optarg);
            break;
        case 'h':
            endhost_print_usage(argv[0]);
            exit(0);
        case '?':
            break;
        default:
            abort();
        }
    }

    if ((input->router_file[0] == '\0') ||
        (input->tcp_port == 0) ||
        (input->udp_port == 0) ||
        (input->stop_threshold == 0)) {
        printf("Please speicify all options\n");
        endhost_print_usage(argv[0]);
        exit(0);
    }

    if ((input->tcp_port > UINT16_MAX) ||
        (input->udp_port > UINT16_MAX)) {
        printf("Please input valid port numbers (< 65535)\n");
        endhost_print_usage(argv[0]);
        exit(0);
    }

    /* Read router file */
    opt = endhost_read_router_file(input);
    if (opt == -1) {
        printf("Error reading router file\n");
        exit(0);
    }

    return;
}


static int
endhost_create_socket (uint32_t     addr,
                       uint16_t     port,
                       uint8_t      recv_ttl)
{
    struct sockaddr_in    lcladdr;
    int                   rc=0, yes;
    int                   sockfd;

    /* Create socket for service */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0){
        perror("Error creating socket. Reason");
        return sockfd;
    }

    /* Set socket options */
    rc = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
                    &yes, sizeof(int));
    if (rc < 0){
        perror("Error setting SO_REUSEADDR. Reason");
        return rc;
    }

    if (recv_ttl) {
        int ttl = DEFAULT_TTL;
        rc = setsockopt(sockfd, IPPROTO_IP, IP_RECVTTL,
                        &ttl, sizeof(ttl));
        if (rc < 0){
            perror("Error setting IP_RECVTTL. Reason");
            return rc;
        }

        rc = setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO,
                        &yes, sizeof(yes));
        if (rc < 0){
            perror("Error setting IP_RECVTTL. Reason");
            return rc;
        }
    }

    /* Fill bind details */
    memset(&lcladdr, 0, sizeof(lcladdr));
    lcladdr.sin_family      = AF_INET;
    lcladdr.sin_port        = htons(port);
    lcladdr.sin_addr.s_addr = htonl(addr);

    /* Bind to local addr-port */
    rc = bind(sockfd, (struct sockaddr *)&lcladdr,
              sizeof(struct sockaddr));
    if (rc < 0){
        perror("Error binding addr-port. Reason");
        return rc;
    }

    return sockfd;
}


static int
endhost_send_signal_to_router (uint32_t addr,
                               uint16_t port)
{
    struct sockaddr_in    srvaddr;
    struct in_addr        saddr = { .s_addr = addr };
    char                  buf[INET_ADDRSTRLEN];
    int                   sockfd, rc;

    /* Create TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){
        perror("Error creating socket. Reason");
        return sockfd;
    }

    memset(&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sin_family      = AF_INET;
    srvaddr.sin_port        = htons(port);
    srvaddr.sin_addr.s_addr = addr; /* Already in n/w order */

    /* Connect to router */
    rc = connect(sockfd, (struct sockaddr *)&srvaddr,
                          sizeof(struct sockaddr_in));
    if (rc < 0) {
        printf("Error connecting to router: %s:%u. Reason: %s\n",
               inet_ntop(AF_INET, &saddr, buf, sizeof(buf)),
               port, strerror(errno));
        return rc;
    }

    /* Send signal to router */
    rc = send(sockfd, ENDHOST_C_SIGNAL, ENDHOST_C_SIGNAL_LEN, 0);
    if (rc < 0) {
        perror("Error sending control signal. Reason");
        return rc;
    }

    fprintf(input.loghdl,
            "%.6f  startMarking  %s  %s\n",
            __time(),
            inet_ntop(AF_INET, &saddr, buf, sizeof(buf)),
            ENDHOST_C_SIGNAL);

    DEBUG_LOG("Sent control signal to router: %s\n",
              inet_ntop(AF_INET, &saddr, buf, sizeof(buf)));

    close(sockfd);
    return 0;
}


static int
endhost_handle_ddos_notification (int sockfd)
{
    static uint8_t  signal_sent = FALSE;
    char            buf[MAX_BUF_LEN] = {0};
    int             i;

    /* Signal already sent to all routers */
    if (signal_sent) {
        return 0;
    }

    DEBUG_LOG("Received ddos notification from traffana\n");

    /* No need to interpret data. Just an indication */
    (void)read(sockfd, buf, sizeof(buf));

    for (i=0; i < input.num_routers; i++) {
        endhost_send_signal_to_router(input.routers[i].router_addr,
                                      input.tcp_port);
    }

    /* Remember that signal has been sent */
    signal_sent = TRUE;
    return 0;
}


static inline void
endhost_handle_traceback_attack (struct in_addr  addr,
                                 uint8_t         ttl)
{
    char        str[INET_ADDRSTRLEN];
    uint8_t     distance, i;

    distance = DEFAULT_TTL - ttl + 1;

    /* Update router TTL */
    for (i=0; i < input.num_routers; i++) {

        /* Skip if distance has been updated */
        if (input.routers[i].router_updated) {
            continue;
        }
        if (input.routers[i].router_addr != addr.s_addr) {
            continue;
        }

        input.routers[i].router_updated = TRUE;
        input.routers[i].router_dist    = distance;

        DEBUG_LOG("Updated router %s distance: %u\n",
                  inet_ntop(AF_INET, &addr, str, sizeof(str)),
                  distance);

        fprintf(input.loghdl,
                "%.6f  %s  %u\n",
                __time(),
                inet_ntop(AF_INET, &addr, str, sizeof(str)),
                distance);
    }
    return;
}


static inline int
endhost_compare_attackers (const void *a,
                           const void *b)
{
    uint32_t  addr1 = *(uint32_t *)a;
    uint32_t  addr2 = *(uint32_t *)b;

    if (addr1 < addr2) return -1;
    if (addr1 > addr2) return 1;
    return 0;
}


static inline void
endhost_handle_traceback_path (char      *buf,
                               uint16_t   buflen)
{
    endhost_attacker_t      *attacker;
    endhost_attacker_t     **found;
    uint32_t                 ddos_ip;
    uint8_t                  num_ips, i, j;
    uint8_t                  new = FALSE;

    num_ips = buf[TRACEBACK_MAGIC_SZ + 1];
    ddos_ip = GET_UINT32(&buf[TRACEBACK_MAGIC_SZ + 2]);

    /* Check if we know this flow */
    found = tfind(&ddos_ip, &attacker_tree, endhost_compare_attackers);

    if (found == NULL) {
        /* Allocate new attacker */
        attacker = calloc(1, sizeof(endhost_attacker_t));
        assert(attacker != NULL);
        new = TRUE;

    } else {
        attacker = *(endhost_attacker_t **)found;
        if (attacker->attacker_n_nodes >= num_ips) {
            /* We already have the best path */
            return;
        }
    }

    attacker->attacker_addr    = ddos_ip;
    attacker->attacker_n_nodes = num_ips;

    /* Store the path */
    j = TRACEBACK_MAGIC_SZ + 2;
    for (i=0; i < num_ips; i++) {
        attacker->attacker_nodes[i] = GET_UINT32(&buf[j]);
        j += sizeof(uint32_t);
    }

    if (new) {
        found = tsearch(attacker, &attacker_tree, endhost_compare_attackers);
        assert(*found == attacker);
    }

    return;
}


static void
endhost_print_attacker_path (const void  *node,
                             const VISIT  which,
                             const int    depth)
{
    endhost_attacker_t   *attacker;
    struct in_addr        addr;
    char                  buf[INET_ADDRSTRLEN];
    int8_t                j=0, i=1;

    attacker = *(endhost_attacker_t **)node;
    if (attacker->attacker_visited) {
        return;
    }

    /* Mark this attacker as visited */
    attacker->attacker_visited = TRUE;

    /* First print own IP */
    addr.s_addr = htonl(self_addr);
    fprintf(input.loghdl, "%s, ",
            inet_ntop(AF_INET, &addr, buf, sizeof(buf)));
    printf("%s, ", buf);


    /* Print the path now */
    for (j = attacker->attacker_n_nodes-1; j >0; j--) {
        addr.s_addr = htonl(attacker->attacker_nodes[j]);
        fprintf(input.loghdl, "%s %u, ",
                inet_ntop(AF_INET, &addr, buf, sizeof(buf)),
                i);
        printf("%s %u, ", buf, i);
        i += 1;
    }

    addr.s_addr = htonl(attacker->attacker_nodes[0]);
    fprintf(input.loghdl, "%s\n",
            inet_ntop(AF_INET, &addr, buf, sizeof(buf)));
    printf("%s\n", buf);
    fflush(input.loghdl);
    return;
}


static int
endhost_handle_traceback_message (int sockfd)
{
    struct cmsghdr     *cmsg;
    struct in_pktinfo  *pi;
    struct msghdr       msg;
    struct iovec        iov[1];
    struct sockaddr_in  addr;
    char                str[INET_ADDRSTRLEN];
    static int          num_msgs = 0;
    uint32_t            ttl = 0;
    char                buf[CMSG_SPACE(MAX_BUF_LEN)];
    char                iovb[MAX_BUF_LEN]    = {0};
    int                 rc;

    memset(&msg, 0, sizeof(msg));
    iov[0].iov_base    = iovb;
    iov[0].iov_len     = sizeof(iovb);
    msg.msg_iov        = iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = buf;
    msg.msg_controllen = sizeof(buf);
    msg.msg_name       = &addr;
    msg.msg_namelen    = sizeof(struct sockaddr_in);

    /* Receive msg along with ancillary data */
    rc = recvmsg(sockfd, &msg, 0);
    if (rc < 0) {
        perror("Error receiving message. Reason");
        return rc;
    }

    /* Go over control headers and get TTL */
    for (cmsg = CMSG_FIRSTHDR(&msg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg,cmsg)) {

        if (cmsg->cmsg_level != IPPROTO_IP) {
            continue;
        }

        switch (cmsg->cmsg_type) {
        case IP_TTL:
            ttl = *((int *)CMSG_DATA(cmsg));
            break;

        case IP_PKTINFO:
            pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
            (void)str;
            if (self_addr == 0) {
                self_addr = ntohl(pi->ipi_spec_dst.s_addr);
                DEBUG_LOG("Victim address: %s\n",
                          inet_ntop(AF_INET, &pi->ipi_spec_dst,
                                    str, sizeof(str)));
            }
            break;
        default:
            break;
        }
    }

    /* Increment number of traceback messages */
    num_msgs++;

    /*
     * +---------------------------+
     * |    MAGIC - 0xDEADBEEF     |  4 bytes
     * +---------------------------+
     * |          TYPE             |  1 byte
     * +---------------------------+
     * |    Number of IPs (n)      |  1 byte
     * +---------------------------+
     * |       Attacker IP         |  4 byte
     * +---------------------------+
     * /       Router IP # 1       / 
     * /       Router IP # 2       /  (n-1) * 4 bytes
     * .............................
     */

    /* Valid assertion */
    assert(GET_UINT32(iovb) == TRACEBACK_MAGIC); 

    switch (iovb[TRACEBACK_MAGIC_SZ]) {
    case TRACEBACK_MSGTYPE_ATTACK:
        endhost_handle_traceback_attack(addr.sin_addr, ttl);
        break;

    case TRACEBACK_MSGTYPE_PATH:
        endhost_handle_traceback_path(iovb, 0);
        break;

    default:
        assert(0);
    }

    /*
     * Reconstruct path to each attacker once
     * stop threshold has been reached
     */
    if (num_msgs == input.stop_threshold) {
        twalk(attacker_tree, endhost_print_attacker_path);
        return 1;
    }

    return 0;
}


static int
endhost_listen_loop (int ddos_sockfd, int trbak_sockfd)
{
    int    rc;

    /* Listen */
    for (;;)
    {
        fd_set    rfds;
        int       maxfd;

        FD_ZERO(&rfds);
        FD_SET(ddos_sockfd, &rfds);
        FD_SET(trbak_sockfd, &rfds);
        maxfd = max(ddos_sockfd, trbak_sockfd);

        /* Use select for multiplexing */
        rc = select((maxfd+ 1), &rfds, NULL, NULL, NULL);
        if (rc < 0){
            perror("Error on select. Reason");
            break;
        }

        if (FD_ISSET(ddos_sockfd, &rfds)) {
            endhost_handle_ddos_notification(ddos_sockfd);

        } else if (FD_ISSET(trbak_sockfd, &rfds)) {
            rc = endhost_handle_traceback_message(trbak_sockfd);
            if (rc) {
                break;
            }
        }
    }

    return rc;
}


static inline void
endhost_create_logfile (endhost_input_t  *input)
{
    char  hostname[MAX_NAME_LEN];
    char  filename[MAX_NAME_LEN+16];
    int   ret;

    /* Store hostname upfront */
    ret = gethostname(hostname, MAX_NAME_LEN);
    assert(ret == 0);

    snprintf(filename, MAX_NAME_LEN+16,
             "%s.endhost.log", hostname);

    input->loghdl = fopen(filename, "w+");
    if (input->loghdl == NULL) {
        perror("Error creating output file. Reason");
        exit(0);
    }
    return;
}


static void
endhost_free_attacker (void *node)
{
    free(node);
}


static int
endhost_send_end_signal_to_all_router (void)
{
    struct sockaddr_in    srvaddr;
    DEBUG_VAR(char,       buf[INET_ADDRSTRLEN]);
    int                   sockfd, rc, i;

    /* Create UDP socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0){
        perror("Error creating socket. Reason");
        return sockfd;
    }

    for (i=0; i < input.num_routers; i++) {
        memset(&srvaddr, 0, sizeof(srvaddr));
        srvaddr.sin_family      = AF_INET;
        srvaddr.sin_port        = htons(input.tcp_port);
        srvaddr.sin_addr.s_addr = input.routers[i].router_addr;

        /* Send signal to router */
        rc = sendto(sockfd, ENDHOST_E_SIGNAL, ENDHOST_E_SIGNAL_LEN,
                    0, (struct sockaddr *)&srvaddr,
                    sizeof(struct sockaddr_in));
        if (rc < 0) {
            perror("Error sending end signal. Reason");
            return rc;
        }

        DEBUG_LOG("Sent end signal to router: %s\n",
                  inet_ntop(AF_INET, &srvaddr.sin_addr,
                            buf, sizeof(buf)));
    }

    close(sockfd);
    return 0;
}


int
main (int   argc,
      char *argv[])
{
    int     ddos_sockfd;
    int     trbak_sockfd;

    /* Read input */
    bzero(&input, sizeof(input));

    /* Read input */
    endhost_read_input(&input, argv, argc);

    /* Create logfile */
    endhost_create_logfile(&input);

    /* DDOS listen socket */
    ddos_sockfd = endhost_create_socket(INADDR_LOOPBACK,
                                        ENDHOST_NOTIF_PORT,
                                        FALSE);
    if (ddos_sockfd < 0) {
        return ddos_sockfd;
    }

    /* Traceback message socket */
    trbak_sockfd = endhost_create_socket(INADDR_ANY,
                                         input.udp_port,
                                         TRUE);
    if (trbak_sockfd < 0) {
        return ddos_sockfd;
    }

    /* Start listening loop */
    endhost_listen_loop(ddos_sockfd, trbak_sockfd);

    /* Ask all routers to stop marking */
    endhost_send_end_signal_to_all_router();

    /* Free resources */
    close(ddos_sockfd);
    close(trbak_sockfd);
    tdestroy(attacker_tree, endhost_free_attacker);

    if (input.routers) {
        free(input.routers);
    }
    return 0;
}
