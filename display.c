/**
 * display.c — Output and statistics display
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "display.h"
#include "argparse.h"
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

/* External globals from mmt_handler.c */
extern uint64_t nb_packets;
extern uint64_t nb_ipv4_sessions;
extern uint64_t nb_ipv6_sessions;
extern uint64_t nb_protocols;
extern uint64_t data_volume;
extern struct timeval *init_time;
extern struct timeval *end_time;

/* Extern from argparse.c */
extern char filename[MAX_FILENAME_SIZE + 1];

/* Protocol path detail flag — set by argparse via dispatch */
extern int proto_path_detail;

/* Extern from mmt_handler.c */
extern mmt_handler_t *mmt_get_handler(void);

typedef struct proto_info_struct {
    const char *name;
    uint64_t pkts;
    uint64_t volume;
    uint64_t payload;
    struct proto_info_struct *prev;
    struct proto_info_struct *next;
} proto_info_t;

static proto_info_t *head = NULL;

static int proto_hierarchy_ids_to_str(const proto_hierarchy_t *proto_hierarchy, char *dest) {
    int offset = 0;
    if (proto_hierarchy->len < 1) {
        offset += sprintf(dest, ".");
    } else {
        int index = 1;
        offset += sprintf(dest, "%s", get_protocol_name_by_id(proto_hierarchy->proto_path[index]));
        index++;
        for (; index < proto_hierarchy->len && index < 16; index++) {
            offset += sprintf(&dest[offset], ".%s", get_protocol_name_by_id(proto_hierarchy->proto_path[index]));
        }
    }
    return offset;
}

static void insert_proto_info(proto_info_t *p_info) {
    if (head == NULL) {
        head = p_info;
        return;
    }

    proto_info_t *current = head;
    while (current != NULL) {
        if (p_info->pkts > current->pkts) {
            p_info->next = current;
            p_info->prev = current->prev;
            if (current->prev != NULL) {
                current->prev->next = p_info;
            } else {
                head = p_info;
            }
            current->prev = p_info;
            return;
        }
        if (current->next == NULL) {
            current->next = p_info;
            p_info->prev = current;
            return;
        }
        current = current->next;
    }
}

static void protocols_stats(uint32_t proto_id, void *args) {
    if (proto_id == 1) return; /* Ignore PROTO_META */

    proto_statistics_t *proto_stats = get_protocol_stats(args, proto_id);
    if (proto_stats != NULL) {
        nb_protocols++;
        proto_info_t *p_info = (proto_info_t *)malloc(sizeof(proto_info_t));
        memset(p_info, 0, sizeof(proto_info_t));
        const char *proto_name = get_protocol_name_by_id(proto_id);
        p_info->name = proto_name;

        while (proto_stats != NULL) {
            if (proto_stats->touched) {
                p_info->pkts += proto_stats->packets_count;
                p_info->volume += proto_stats->data_volume;
                p_info->payload += proto_stats->payload_volume;

                if (proto_path_detail == 1) {
                    proto_hierarchy_t proto_hierarchy = {0};
                    get_protocol_stats_path((mmt_handler_t *)args, proto_stats, &proto_hierarchy);
                    char path[128];
                    proto_hierarchy_ids_to_str(&proto_hierarchy, path);
                    printf("%10lu %10lu %10lu %60s\n",
                           proto_stats->packets_count,
                           proto_stats->data_volume,
                           proto_stats->payload_volume,
                           path);
                }
            }
            proto_stats = proto_stats->next;
        }
        insert_proto_info(p_info);
    }
}

void display_stats(void) {
    mmt_handler_t *mmt = mmt_get_handler();

    printf("\n- - - - - - MMT-READER STATS - - - - -\n\n");
    if (proto_path_detail) printf("Protocol statistics with the protocol path:\n\n");
    printf("\t#pkts\t#volume\t#payload\t#proto_path\n");
    iterate_through_protocols(protocols_stats, mmt);
    printf("\nProtocol statistics:\n\n");
    printf("\t#pkts\t#volume\t#payload\t#proto_name\n");

    proto_info_t *current = head;
    while (current != NULL) {
        proto_info_t *next = current->next;
        printf("%10lu %10lu %10lu %20s\n", current->pkts, current->volume, current->payload, current->name);
        free(current);
        current = next;
    }

    printf(">>>>>> INPUT STATISTICS <<<<<< \n\n");
    printf("\tInput: %s\n", filename);
    printf("\tPackets: %lu\n", nb_packets);
    printf("\tData: %lu bytes\n", data_volume);
    printf("\tSessions: %lu\n", nb_ipv4_sessions + nb_ipv6_sessions);
    printf("\tProtocols: %lu\n", nb_protocols);
    if (end_time && init_time) {
        double duration = (double)(end_time->tv_sec - init_time->tv_sec);
        if (duration > 0) {
            printf("\tDuration: %lu seconds\n", (unsigned long)duration);
            printf("\tBandwidth: %.2f bytes/second\n", 1.0 * data_volume / duration);
            printf("\tpps: %.2f packets/second\n", 1.0 * nb_packets / duration);
            printf("\tfps: %.2f sessions/second\n\n", 1.0 * (nb_ipv4_sessions + nb_ipv6_sessions) / duration);
        }
    }
}
