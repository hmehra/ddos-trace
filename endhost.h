/*
 * endhost.h
 * Endhost header file
 *
 * @author : Himanshu Mehra
 * @email  : hmehra@usc.edu
 * @project: ISI Project
 */

#ifndef __ENDHOST_H__
#define __ENDHOST_H__

#include <stdint.h>
#include <assert.h>
#include "common.h"

/* Constants */
#define ENDHOST_C_SIGNAL        "DDOS detected"
#define ENDHOST_C_SIGNAL_LEN    strlen(ENDHOST_C_SIGNAL)

#define ENDHOST_E_SIGNAL        "End marking"
#define ENDHOST_E_SIGNAL_LEN    strlen(ENDHOST_E_SIGNAL)



typedef struct {
    uint32_t            router_addr;
    uint8_t             router_dist;
    uint8_t             router_updated;
} endhost_router_t;


typedef struct {
    char                router_file[MAX_NAME_LEN];
    uint32_t            stop_threshold;
    uint16_t            tcp_port;
    uint16_t            udp_port;
    uint32_t            num_routers;
    endhost_router_t   *routers;
    FILE               *loghdl;
} endhost_input_t;


typedef struct {
    uint32_t            attacker_addr;
    uint32_t            attacker_nodes[MAX_ROUTERS];
    uint8_t             attacker_n_nodes;
    uint8_t             attacker_visited;
    uint8_t             attacker_pad[2];
} endhost_attacker_t;


#endif  /* #ifndef __ENDHOST_H__ */
