/*
 * traffana.h
 * Traffic Analyzer header file
 *
 * @author : Himanshu Mehra
 * @email  : hmehra@usc.edu
 * @project: ISI Project
 */

#ifndef __TRAFFANA_H__
#define __TRAFFANA_H__

#include <stdint.h>
#include <assert.h>
#include "common.h"

/* Constants */
#define TRAFFANA_DEFAULT_EPOCH      1   /* second */
#define TRAFFANA_MAX_FLOWS          2048
#define TRAFFANA_MAX_ATTACKERS      65535

#define TRAFFANA_FLOW_MON_2TUPLE    2
#define TRAFFANA_FLOW_MON_5TUPLE    5


typedef struct {
    char            pcap_file[MAX_NAME_LEN];
    char            output_file[MAX_NAME_LEN];
    char            interface[MAX_NAME_LEN];
    double          epoch;
    uint8_t         verbose;
    uint8_t         tuple_mode;
    double          global_time;
    uint32_t        pkt_threshold;
    uint32_t        byte_threshold;
    uint32_t        flow_threshold;
    uint32_t        src_threshold;
    FILE           *loghdl;
    FILE           *attack_loghdl;
} traffana_input_t;


typedef struct {
    uint32_t        src_addr;   /* network order */
    uint32_t        dst_addr;   /* network order */
    uint16_t        src_port;   /* network order */
    uint16_t        dst_port;   /* network order */
    uint8_t         proto;
} traffana_flow_t;


typedef struct {
    uint32_t        num_pkts;
    uint32_t        num_bytes;
    uint32_t        num_icmp_pkts;
    uint32_t        num_udp_pkts;
    uint32_t        num_tcp_pkts;
    uint32_t        num_other_pkts;
    uint32_t        num_flows;
    uint32_t        num_tcp_flows;
    uint32_t        num_udp_flows;
    uint32_t        num_icmp_flows;
    uint32_t        num_src_addrs;
    uint32_t        attack_detected;
} traffana_epoch_t;


#endif  /* #ifndef __TRAFFANA_H__ */
