/**
 * mmt_handler.c — MMT handler setup and packet processing
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include "mmt_handler.h"
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "display.h"

/* Global statistics */
uint64_t nb_packets = 0;
uint64_t nb_ipv4_sessions = 0;
uint64_t nb_ipv6_sessions = 0;
uint64_t nb_protocols = 0;
uint64_t data_volume = 0;
struct timeval *init_time = NULL;
struct timeval *end_time = NULL;

static mmt_handler_t *g_mmt_handler = NULL;

void mmt_init_extraction(void) {
    init_extraction();
}

mmt_handler_t *mmt_create_handler(int dlt, int flags, char *errbuf) {
    g_mmt_handler = mmt_init_handler(dlt, flags, errbuf);
    return g_mmt_handler;
}

void mmt_setup_classification(mmt_handler_t *mmt,
                               int ip_classify,
                               int hostname_classify,
                               int port_classify) {
    if (ip_classify) {
        printf("Enable classification by IP address");
        enable_ip_address_classify(mmt);
    } else {
        disable_ip_address_classify(mmt);
    }

    if (hostname_classify) {
        printf("Enable classification by Hostname");
        enable_hostname_classify(mmt);
    } else {
        disable_hostname_classify(mmt);
    }

    if (port_classify) {
        printf("Enable classification by Port number");
        enable_port_classify(mmt);
    } else {
        disable_port_classify(mmt);
    }
}

static void attributes_iterator(attribute_metadata_t *attribute, uint32_t proto_id, void *args) {
    register_extraction_attribute(args, proto_id, attribute->id);
}

static void protocols_iterator(uint32_t proto_id, void *args) {
    iterate_through_protocol_attributes(proto_id, attributes_iterator, args);
}

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    uint64_t *packet_count = (uint64_t *)get_attribute_extracted_data(ipacket, PROTO_META, PROTO_PACKET_COUNT);
    if (packet_count != NULL) {
        nb_packets = *packet_count;
    }

    uint64_t *data_count = (uint64_t *)get_attribute_extracted_data(ipacket, PROTO_META, PROTO_DATA_VOLUME);
    if (data_count != NULL) {
        data_volume = *data_count;
    }

    if (ipacket->packet_id == 1) {
        struct timeval *first_time = (struct timeval *)get_attribute_extracted_data(ipacket, PROTO_META, PROTO_FIRST_PACKET_TIME);
        init_time = first_time;
    }

    struct timeval *last_time = (struct timeval *)get_attribute_extracted_data(ipacket, PROTO_META, PROTO_LAST_PACKET_TIME);
    end_time = last_time;

    return 0;
}

static void new_ipv4_session_handler(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void)ipacket;
    (void)attribute;
    (void)user_args;
    nb_ipv4_sessions++;
}

static void new_ipv6_session_handler(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
    (void)ipacket;
    (void)attribute;
    (void)user_args;
    nb_ipv6_sessions++;
}

void mmt_register_handlers(mmt_handler_t *mmt) {
    /* Iterate through protocols to register all attributes */
    iterate_through_protocols(protocols_iterator, mmt);
    register_packet_handler(mmt, 1, packet_handler, NULL);

    /* Register session creation callbacks */
    register_attribute_handler(mmt, PROTO_IP, PROTO_SESSION, new_ipv4_session_handler, NULL, NULL);
    register_attribute_handler(mmt, PROTO_IPV6, PROTO_SESSION, new_ipv6_session_handler, NULL, NULL);
}

static void signal_handler(int type) {
    printf("\nINFO: reception of signal %d\n", type);
    fflush(stderr);
    mmt_cleanup();
    exit(0);
}

void mmt_setup_signals(void) {
    sigset_t signal_set;
    sigfillset(&signal_set);
    signal(SIGINT, signal_handler);
}

void mmt_cleanup(void) {
    display_stats();
    if (g_mmt_handler) {
        mmt_close_handler(g_mmt_handler);
        close_extraction();
    }
}

mmt_handler_t *mmt_get_handler(void) {
    return g_mmt_handler;
}
