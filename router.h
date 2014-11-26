/*
 * router.h
 * Router tool header file
 *
 * @author : Himanshu Mehra
 * @email  : hmehra@usc.edu
 * @project: ISI Project
 */

#ifndef __ROUTER_H__
#define __ROUTER_H__

#include <stdint.h>
#include <assert.h>
#include "common.h"


#define TRACEBACK_MAGIC         0xDEADFEED
#define TRACEBACK_MAGIC_SZ      sizeof(TRACEBACK_MAGIC)

#define TRACEBACK_MSG_LEN(n)    \
    (uint32_t)(TRACEBACK_MAGIC_SZ + 2 + ((n)*sizeof(uint32_t)))


#define TRACEBACK_MSGTYPE_ATTACK    1
#define TRACEBACK_MSGTYPE_PATH      2


typedef struct {
    uint32_t        epoch;
    uint16_t        tcp_port;
    uint16_t        udp_port;
    float           probability;
    FILE           *loghdl;
    double          epoch_start;
    uint32_t        epoch_cnt;
    uint32_t        local_addr;
} router_input_t;


typedef struct {
    uint32_t        router_addr;
    uint32_t        victim_addr;
    uint16_t        victim_port;
} router_pcap_loop_t;


#endif  /* #ifndef __ROUTER_H__ */
