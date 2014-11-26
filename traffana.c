/*
 * traffana.c
 * Traffic Analyzer implementation
 *
 * @author : Himanshu Mehra
 * @email  : hmehra@usc.edu
 * @project: ISI Project
 */

#define _GNU_SOURCE
#include <stdio.h>
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
#include "traffana.h"
#include "endhost.h"


/* Global variable */
static traffana_input_t      input;
static struct hsearch_data   saddr_htbl;
static void                 *flow_tree;

#define TRAFFANA_OP_FMT                 \
    "%.6f  %-6u  %-10u  %-4u\n"

#define TRAFFANA_VERBOSE_OP_FMT         \
    "%.6f  %-6u  %-10u  %-4u %-6u %-6u %-6u %-4u %-4u %-4u\n"

#define TRAFFANA_ATTACK_OP_FMT          \
    "%.6f  %.6f  %-6u  %-10u  %-4u\n"

#define TRAFFANA_GET_PKT_TIME(_h_)      \
    ((_h_)->ts.tv_sec + (double)(_h_)->ts.tv_usec/1000000)


static struct option
long_options[] = {
    {"help"      , no_argument      , 0, 'h'},
    {"interface" , required_argument, 0, 'i'},
    {"read"      , required_argument, 0, 'r'},
    {"time"      , required_argument, 0, 'T'},
    {"verbose"   , no_argument      , 0, 'v'},
    {"write"     , required_argument, 0, 'w'},
    {"track"     , required_argument, 0, 'z'},
    {"pktthresh" , required_argument, 0, 'p'},
    {"bytethresh", required_argument, 0, 'b'},
    {"flowthresh", required_argument, 0, 'f'},
    {"srcthresh" , required_argument, 0, 's'},
    {0, 0, 0, 0}
};


static const char *
options_help[] = {
    "Display this help and exit",
    "Interface name to capture from (root)",
    "PCAP file to read packets from",
    "Print packet/byte counts for specified time epoch",
    "Enable verbose mode. Print packet/byte counts",
    "Write the packet counts to a specified filename",
    "Count number of flows based on the 2/5 tuple",
    "Packet threshold to signal an attack",
    "Byte threshold to signal an attack",
    "Flow threshold to signal an attack",
    "Src to dest threshold to signal an attack",
    NULL,
};



static void
traffana_print_usage (char *progname)
{
    int i = 0;

    printf("\nUsage:\n traffana [-r | -i] OPTIONS\n\n");
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
traffana_read_input (traffana_input_t   *input,
                     char              **argv,
                     int                 argc)
{
    int    opt_idx = 0;
    int    opt, can_run = FALSE;

    if (argc < 2) {
        traffana_print_usage(argv[0]);
        exit(0);
    }

    for (;;) {
        opt = getopt_long(argc, argv, "hi:r:T:vw:z:p:b:f:s:",
                          long_options, &opt_idx);

        if (opt == -1) {
            break;  /* End of input */
        }

        switch (opt) {
        case 'i':
            can_run = TRUE;
            strncpy(input->interface, optarg, MAX_NAME_LEN);
            break;
        case 'w':
            if (optarg) {
                strncpy(input->output_file, optarg, MAX_NAME_LEN);
            }
            break;
        case 'r':
            can_run = TRUE;
            strncpy(input->pcap_file, optarg, MAX_NAME_LEN);
            break;
        case 'v':
            input->verbose = TRUE;
            break;
        case 'T':
            input->epoch = atof(optarg);
            break;
        case 'z':
            input->tuple_mode = atoi(optarg);
            if ((input->tuple_mode != TRAFFANA_FLOW_MON_2TUPLE) &&
                (input->tuple_mode != TRAFFANA_FLOW_MON_5TUPLE)) {
                printf("Invalid value for tuple tracking: %u\n",
                       input->tuple_mode);
                traffana_print_usage(argv[0]);
                exit(0);
            }
            break;
        case 'p':
            input->pkt_threshold = atoi(optarg);
            break;
        case 'b':
            input->byte_threshold = atoi(optarg);
            break;
        case 'f':
            input->flow_threshold = atoi(optarg);
            break;
        case 's':
            input->src_threshold = atoi(optarg);
            break;
        case 'h':
            traffana_print_usage(argv[0]);
            exit(0);
        case '?':
            break;
        default:
            abort();
        }
    }

    if (!can_run) {
        traffana_print_usage(argv[0]);
        exit(0);
    }
    if (input->interface[0] && input->pcap_file[0]) {
        printf("Either pcap or interface should be specified\n");
        traffana_print_usage(argv[0]);
        exit(0);
    }

    if (input->tuple_mode == 0) {
        printf("Please specify tuple tracking mode\n");
        traffana_print_usage(argv[0]);
        exit(0);
    }

    /* Init epoch if not provided */
    if (input->epoch == 0) {
        input->epoch = TRAFFANA_DEFAULT_EPOCH;
    }

    /* Init log handle */
    input->loghdl = stdout;
    if (input->output_file[0]) {
        input->loghdl = fopen(input->output_file, "w+");
        if (input->loghdl == NULL) {
            perror("Error opening output file. Reason");
            exit(0);
        }
    }
    return;
}


static inline int
traffana_compare_5_tuple (const void *a,
                          const void *b)
{
    traffana_flow_t   *flow1 = (traffana_flow_t *)a;
    traffana_flow_t   *flow2 = (traffana_flow_t *)b;

    if (flow1->src_addr < flow2->src_addr) return -1;
    if (flow1->src_addr > flow2->src_addr) return 1;
    if (flow1->dst_addr < flow2->dst_addr) return -1;
    if (flow1->dst_addr > flow2->dst_addr) return 1;
    if (flow1->src_port < flow2->src_port) return -1;
    if (flow1->src_port > flow2->src_port) return 1;
    if (flow1->dst_port < flow2->dst_port) return -1;
    if (flow1->dst_port > flow2->dst_port) return 1;
    if (flow1->proto    < flow2->proto)    return -1;
    if (flow1->proto    > flow2->proto)    return 1;
    return 0;
}


static inline int
traffana_compare_2_tuple (const void *a,
                          const void *b)
{
    traffana_flow_t   *flow1 = (traffana_flow_t *)a;
    traffana_flow_t   *flow2 = (traffana_flow_t *)b;

    if (flow1->src_addr < flow2->src_addr) return -1;
    if (flow1->src_addr > flow2->src_addr) return 1;
    if (flow1->dst_addr < flow2->dst_addr) return -1;
    if (flow1->dst_addr > flow2->dst_addr) return 1;
    return 0;
}


void
traffana_free_flow (void *node)
{
    free(node);
}

static inline void
traffana_delete_flow_tree (void)
{
    tdestroy(flow_tree, traffana_free_flow);
    flow_tree = NULL;
}


static inline void
traffana_dump_flow (traffana_flow_t  *flow)
{
#ifdef VERBOSE
    struct in_addr    saddr;
    struct in_addr    daddr;
    char              sbuf[INET_ADDRSTRLEN];
    char              dbuf[INET_ADDRSTRLEN];

    saddr.s_addr = flow->src_addr;
    daddr.s_addr = flow->dst_addr;

    DEBUG_LOG("Inserting in tree ");
    if (input.tuple_mode == TRAFFANA_FLOW_MON_2TUPLE) {
        DEBUG_LOG("%15s => %-15s\n",
                  inet_ntop(AF_INET, &saddr, sbuf, sizeof(sbuf)),
                  inet_ntop(AF_INET, &daddr, dbuf, sizeof(dbuf)));
    } else {
        DEBUG_LOG("%15s:%-5u  => %15s:%-5u  [%u]\n",
                  inet_ntop(AF_INET, &saddr, sbuf, sizeof(sbuf)),
                  ntohs(flow->src_port),
                  inet_ntop(AF_INET, &daddr, dbuf, sizeof(dbuf)),
                  ntohs(flow->dst_port),
                  flow->proto);
    }
#endif
}


static inline void
traffana_notify_endhost (void)
{
    struct sockaddr_in    srvaddr;
    char                  buf[MAX_NAME_LEN] = {0};
    int                   sockfd;
    int                   rc;

    /* Create socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0){
        perror("Error creating socket. Reason");
        return;
    }

    DEBUG_LOG("Attack detected. Notifying endhost\n");

    /* Fill server details */
    memset(&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sin_family      = AF_INET;
    srvaddr.sin_port        = htons(ENDHOST_NOTIF_PORT);
    srvaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    /* Send notification to endhost */
    buf[0] = 'A';
    rc = sendto(sockfd, buf, strlen(buf), 0,
                (struct sockaddr *)&srvaddr,
                sizeof(struct sockaddr_in));
    if (rc < 0) {
        perror("Error notifyinf endhost about DDOS. Reason");
    }

    return;
}

static inline void
traffana_log_attackinfo (traffana_input_t  *input,
                         traffana_epoch_t  *epoch,
                         double             curr_time)
{
    static uint8_t  endhost_notified = FALSE;

    if (!endhost_notified) {
        endhost_notified = TRUE;
        traffana_notify_endhost();
    }

    fprintf(input->attack_loghdl,
            TRAFFANA_ATTACK_OP_FMT,
            curr_time,
            input->global_time,
            epoch->num_pkts,
            epoch->num_bytes,
            epoch->num_flows);
    fflush(input->attack_loghdl);
}


static inline void
traffana_track_source_addr (traffana_flow_t   *key,
                            traffana_epoch_t  *epoch)
{
    traffana_flow_t  *sflow;
    ENTRY            *found = NULL;
    ENTRY             entry;

    entry.key = (void *)&key->src_addr;
    hsearch_r(entry, FIND, &found, &saddr_htbl);

    /* Allocate new source flow */
    if (found)  {
        return;
    }

    sflow = calloc(1, sizeof(traffana_flow_t));
    assert(sflow != NULL);
    memcpy(sflow, key, sizeof(traffana_flow_t));
    epoch->num_src_addrs++;

    /* Enter into hash table */
    entry.key  = (void *)&sflow->src_addr;
    entry.data = sflow;
    hsearch_r(entry, ENTER, &found, &saddr_htbl);
    assert(found != NULL);
    return;
}


static inline void
traffana_extract_flow_info (traffana_input_t  *input,
                            traffana_epoch_t  *epoch,
                            const uint8_t     *data,
                            double             curr_time)
{
    comparison_fn_t          compare_func;
    traffana_flow_t          key;
    traffana_flow_t        **found = NULL;
    traffana_flow_t         *flow  = NULL;
    struct ether_header     *ether = NULL;
    struct iphdr            *ip    = NULL;
    struct tcphdr           *tcp   = NULL;
    struct udphdr           *udp   = NULL;

    ether = (struct ether_header *)data;
    ip    = (struct iphdr *)(ether + 1);

    key.src_addr = ip->saddr;
    key.dst_addr = ip->daddr;
    key.proto    = ip->protocol;

    switch (ip->protocol) {
    case IPPROTO_UDP:
        epoch->num_udp_pkts++;
        udp = (struct udphdr *)(ip + 1);
        key.src_port = udp->source;
        key.dst_port = udp->dest;
        break;

    case IPPROTO_TCP:
        epoch->num_tcp_pkts++;
        tcp = (struct tcphdr *)(ip + 1);
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
        break;

    case IPPROTO_ICMP:
        epoch->num_icmp_pkts++;
        key.src_port = 0;
        key.dst_port = 0;
        break;

    default:
        epoch->num_other_pkts++;
        /* Other flows not to be accounted */
        return;
    }


    /* Get the tuple comparison function */
    if (input->tuple_mode == TRAFFANA_FLOW_MON_2TUPLE) {
        compare_func = traffana_compare_2_tuple;
    } else {
        compare_func = traffana_compare_5_tuple;
    }

    /* Check if we know this flow */
    found = tfind(&key, &flow_tree, compare_func);
    if (found) {
        return;
    }

    /* New flow. Increment counters */
    epoch->num_flows++;
    if (key.proto == IPPROTO_UDP) {
        epoch->num_udp_flows++;
    } else if (key.proto == IPPROTO_TCP) {
        epoch->num_tcp_flows++;
    } else {
        epoch->num_icmp_flows++;
    }

    /* Allocate new flow */
    flow = calloc(1, sizeof(traffana_flow_t));
    assert(flow != NULL);
    memcpy(flow, &key, sizeof(traffana_flow_t));

    traffana_dump_flow(flow);

    /* Insert in flow_tree */
    found = tsearch(flow, &flow_tree, compare_func);
    assert(*found == flow);

    /*
     * CHECK IF WE KNOW THIS SOURCE
     */
    if (input->src_threshold) {
        traffana_track_source_addr(&key, epoch);
    }

    if (epoch->attack_detected) {
        /* If attack detected, no need to log again */
        return;
    }

    /* Check various thresholds for attack */
    if (((input->pkt_threshold) &&
         (epoch->num_pkts > input->pkt_threshold))
        ||
        ((input->byte_threshold) &&
         (epoch->num_bytes > input->byte_threshold))
        ||
        ((input->flow_threshold) &&
         (epoch->num_flows > input->flow_threshold))
        ||
        ((input->src_threshold) &&
         (epoch->num_src_addrs > input->src_threshold))) {

        epoch->attack_detected = TRUE;
        traffana_log_attackinfo(input, epoch, curr_time);
    }

    return;
}


static inline void
traffana_print_stats (traffana_epoch_t  *epoch,
                      traffana_input_t  *input)
{
    if (input->verbose) {
        fprintf(input->loghdl,
                TRAFFANA_VERBOSE_OP_FMT,
                input->global_time,
                epoch->num_pkts,
                epoch->num_bytes,
                epoch->num_flows,
                epoch->num_tcp_pkts,
                epoch->num_udp_pkts,
                epoch->num_icmp_pkts,
                epoch->num_other_pkts,
                epoch->num_tcp_flows,
                epoch->num_udp_flows);
    } else {
        fprintf(input->loghdl,
                TRAFFANA_OP_FMT,
                input->global_time,
                epoch->num_pkts,
                epoch->num_bytes,
                epoch->num_flows);
    }
    fflush(input->loghdl);
}


static inline void
traffana_log_pkt_per_epoch (traffana_epoch_t    *epoch,
                            traffana_input_t    *input,
                            struct pcap_pkthdr  *hdr,
                            const uint8_t       *data)
{
    struct ether_header     *ether;
    static double            curr_time   = 0;
    static uint32_t          curr_pkt    = 0;


    /* Check if IP or IPv6 packet */
    ether = (struct ether_header *)data;
    if (ether->ether_type != htons(ETHERTYPE_IP)) {
        return;
    }

    /* Start Global Clock @ arrival of first packet */
    if (input->global_time == 0) {
        input->global_time = TRAFFANA_GET_PKT_TIME(hdr);
    }

    curr_time = TRAFFANA_GET_PKT_TIME(hdr);
    if (curr_time - input->global_time > input->epoch) {
        uint16_t num_epochs;
        uint16_t i;

        num_epochs = (curr_time - input->global_time) / input->epoch;
        for (i=0; i < num_epochs; i++) {
            traffana_print_stats(epoch, input);
            input->global_time += input->epoch;

            /* Reset counters. Delete flow_tree, src htable */
            memset(epoch, 0, sizeof(*epoch));
            traffana_delete_flow_tree();

            if (input->src_threshold) {
                hdestroy_r(&saddr_htbl);
                memset(&saddr_htbl, 0, sizeof(saddr_htbl));
                hcreate_r(TRAFFANA_MAX_ATTACKERS, &saddr_htbl);
            }
        }
    }

    epoch->num_pkts++;
    epoch->num_bytes += hdr->len;

    /* Extract flow info */
    traffana_extract_flow_info(input, epoch, data, curr_time); 
    curr_pkt++;

    return;
}


static inline void
traffana_analyze_pcap (traffana_input_t   *input)
{
    traffana_epoch_t     epoch;
    struct pcap_pkthdr  *hdr;
    const uint8_t       *data;
    pcap_t              *pcap_hdl;
    char                 errbuf[PCAP_ERRBUF_SIZE];

    /* Open pcap file */
    pcap_hdl = pcap_open_offline(input->pcap_file, errbuf);
    if (pcap_hdl == NULL) {
        printf("%s\n", errbuf);
        return;
    }

    /* Retrieve the packets from the file */
    memset(&epoch, 0, sizeof(epoch));
    while (pcap_next_ex(pcap_hdl, &hdr, &data) >= 0) {
        traffana_log_pkt_per_epoch(&epoch, input, hdr, data);
    }

    /*
     * Print packets that if epoch did not
     * complete before the end of file
     */
    if (epoch.num_pkts) {
        traffana_print_stats(&epoch, input);
    }

    fclose(input->loghdl);
    return;
}


static inline void
traffana_capture_live (traffana_input_t   *input)
{
    traffana_epoch_t     epoch;
    struct pcap_pkthdr   hdr;
    const uint8_t       *data;
    pcap_t              *pcap_hdl;
    char                 errbuf[PCAP_ERRBUF_SIZE];

    /* Open pcap file */
    pcap_hdl = pcap_open_live(input->interface, BUFSIZ, 0, -1, errbuf);
    if (pcap_hdl == NULL) {
        printf("%s\n", errbuf);
        return;
    }

    memset(&epoch, 0, sizeof(epoch));
    for (;;) {
        data = pcap_next(pcap_hdl, &hdr);
        if (data == NULL) {
            continue;
        }

        traffana_log_pkt_per_epoch(&epoch, input, &hdr, data);
    }

    /*
     * Print packets that if epoch did not
     * complete before the end of file
     */
    if (epoch.num_pkts) {
        traffana_print_stats(&epoch, input);
    }
    return;
}


void
traffana_handle_sigint (int sig)
{
    /* Catch Ctrl-C and flush all buffers */
    fflush(input.loghdl);
    fflush(input.attack_loghdl);
    traffana_delete_flow_tree();

    if (input.src_threshold) {
        hdestroy_r(&saddr_htbl);
    }
    exit(0);
}


static inline void
traffana_create_attack_logfile (traffana_input_t  *input)
{
    char  hostname[MAX_NAME_LEN];
    char  filename[MAX_NAME_LEN+16];
    int   ret;

    /* Store hostname upfront */
    ret = gethostname(hostname, MAX_NAME_LEN);
    assert(ret == 0);

    snprintf(filename, MAX_NAME_LEN+16,
             "%s.attackinfo", hostname);

    input->attack_loghdl = fopen(filename, "w+");
    if (input->attack_loghdl == NULL) {
        perror("Error creating output file. Reason");
        exit(0);
    }
    return;
}


int
main (int   argc,
      char *argv[])
{
    int     rc;

    /* Read input */
    bzero(&input, sizeof(input));

    /* Read input */
    traffana_read_input(&input, argv, argc);

    /* Initialize source addr hash table */
    if (input.src_threshold) {
        memset(&saddr_htbl, 0, sizeof(saddr_htbl));
        rc = hcreate_r(TRAFFANA_MAX_ATTACKERS, &saddr_htbl);
        assert(rc);
    }

    /* Create attack logfile */
    traffana_create_attack_logfile(&input);

    /* Read from pcap/interface  */
    if (input.pcap_file[0]) {
        traffana_analyze_pcap(&input);

    } else if (input.interface[0]) {
        /* Handle SIGINT for flushing buffer */
        signal(SIGINT, traffana_handle_sigint);
        traffana_capture_live(&input);
    }

    /* Destroy flow tree now */
    traffana_delete_flow_tree();
    if (input.src_threshold) {
        hdestroy_r(&saddr_htbl);
    }

    return 0;
}
