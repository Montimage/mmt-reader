/**
 * flows.c — Top talkers, reported from MMT-DPI sessions
 *
 * The DPI already tracks every session it sees: the 5-tuple lives in the
 * session key, the byte and packet counters are maintained per session,
 * and the protocol hierarchy names the application. This module only
 * keeps a record of the sessions seen so they survive a session timeout,
 * and ranks them by volume.
 *
 * Nothing here parses packet bytes. Ethernet, VLAN/QinQ, IP options,
 * IPv6 extension headers, fragments and tunnels are the DPI's business,
 * and a flow is whatever the DPI calls a session — both directions of a
 * conversation, counted together.
 */
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include "flows.h"
#include "tcpip/mmt_tcpip.h"

/* ------------------------------------------------------------------ */
/* Internal types                                                      */
/* ------------------------------------------------------------------ */

#define FLOW_TABLE_BITS  11            /* 2048 buckets                 */
#define FLOW_TABLE_SIZE  (1U << FLOW_TABLE_BITS)
#define FLOW_MAX_FLOWS   (FLOW_TABLE_SIZE * 4)

/** Identifier of the packet handler this module registers with the DPI */
#define FLOWS_PACKET_HANDLER_ID 1

typedef struct flow_entry {
    uint64_t session_id;               /**< DPI session identifier      */
    uint8_t  is_ipv6;
    uint8_t  has_tuple;                /**< Addresses/ports resolved    */
    uint32_t client4;                  /**< Network byte order          */
    uint32_t server4;
    uint8_t  client6[16];
    uint8_t  server6[16];
    uint16_t client_port;
    uint16_t server_port;
    uint64_t bytes;                    /**< From get_session_byte_count */
    uint64_t pkts;                     /**< From get_session_packet_count */
    const char *app;                   /**< DPI application name        */
    struct flow_entry *next;           /**< Next entry in the bucket    */
} flow_entry_t;

struct flows {
    flow_entry_t *buckets[FLOW_TABLE_SIZE];
    flow_entry_t *flows[FLOW_MAX_FLOWS];
    size_t nflows;
    mmt_handler_t *mmt;                /**< Handler attached to, or NULL */
};

/* ------------------------------------------------------------------ */
/* Flow table                                                          */
/* ------------------------------------------------------------------ */

/**
 * Find the record of a session, creating it on first sight.
 * @return The record, or NULL when the table is full or out of memory
 */
static flow_entry_t *flow_get_or_create(flows_t *f, uint64_t session_id) {
    /* Session ids are a dense counter, so the low bits spread evenly */
    uint32_t bidx = (uint32_t)(session_id & (FLOW_TABLE_SIZE - 1));
    flow_entry_t *e = f->buckets[bidx];

    while (e != NULL) {
        if (e->session_id == session_id) {
            return e;
        }
        e = e->next;
    }

    if (f->nflows >= FLOW_MAX_FLOWS) return NULL; /* table full — drop */

    e = (flow_entry_t *)calloc(1, sizeof(flow_entry_t));
    if (e == NULL) return NULL;
    e->session_id = session_id;
    e->next = f->buckets[bidx];
    f->buckets[bidx] = e;
    f->flows[f->nflows++] = e;
    return e;
}

/* ------------------------------------------------------------------ */
/* Session data extraction (MMT-DPI)                                   */
/* ------------------------------------------------------------------ */

/**
 * Fill in the flow's endpoints from the DPI session key.
 *
 * The client/server attributes are derived from the session key rather
 * than from the current packet, so both directions of the conversation
 * report the same endpoints: client is the side that opened the session.
 *
 * @param e        Flow record to fill
 * @param ipacket  Packet being processed
 * @param session  Session the packet belongs to
 * @return         1 when the endpoints were resolved, 0 otherwise
 */
static int flow_fill_tuple(flow_entry_t *e, const ipacket_t *ipacket,
                           const mmt_session_t *session) {
    /* Index of the IP layer the session sits on — a tunnelled session
     * carries an inner IP header, which is the one that identifies it */
    unsigned index = (unsigned)get_session_protocol_index(session);
    uint32_t proto_id = get_protocol_id_at_index(ipacket, index);

    if (proto_id == PROTO_IP) {
        uint32_t *client = (uint32_t *)get_attribute_extracted_data_at_index(
            (ipacket_t *)ipacket, PROTO_IP, IP_CLIENT_ADDR, index);
        uint32_t *server = (uint32_t *)get_attribute_extracted_data_at_index(
            (ipacket_t *)ipacket, PROTO_IP, IP_SERVER_ADDR, index);
        uint16_t *cport = (uint16_t *)get_attribute_extracted_data_at_index(
            (ipacket_t *)ipacket, PROTO_IP, IP_CLIENT_PORT, index);
        uint16_t *sport = (uint16_t *)get_attribute_extracted_data_at_index(
            (ipacket_t *)ipacket, PROTO_IP, IP_SERVER_PORT, index);

        if (client == NULL || server == NULL) return 0;

        e->is_ipv6 = 0;
        e->client4 = *client;
        e->server4 = *server;
        e->client_port = (cport != NULL) ? *cport : 0;
        e->server_port = (sport != NULL) ? *sport : 0;
        return 1;
    }

    if (proto_id == PROTO_IPV6) {
        void *client = get_attribute_extracted_data_at_index(
            (ipacket_t *)ipacket, PROTO_IPV6, IP6_CLIENT_ADDR, index);
        void *server = get_attribute_extracted_data_at_index(
            (ipacket_t *)ipacket, PROTO_IPV6, IP6_SERVER_ADDR, index);
        uint16_t *cport = (uint16_t *)get_attribute_extracted_data_at_index(
            (ipacket_t *)ipacket, PROTO_IPV6, IP6_CLIENT_PORT, index);
        uint16_t *sport = (uint16_t *)get_attribute_extracted_data_at_index(
            (ipacket_t *)ipacket, PROTO_IPV6, IP6_SERVER_PORT, index);

        if (client == NULL || server == NULL) return 0;

        e->is_ipv6 = 1;
        memcpy(e->client6, client, sizeof(e->client6));
        memcpy(e->server6, server, sizeof(e->server6));
        e->client_port = (cport != NULL) ? *cport : 0;
        e->server_port = (sport != NULL) ? *sport : 0;
        return 1;
    }

    /* A session on something other than IP — nothing to report here */
    return 0;
}

/**
 * Packet handler registered with the DPI: records the packet's session.
 *
 * Counters are read back from the session on every packet rather than
 * accumulated here, so they stay exactly what the DPI accounted for.
 */
static int flows_packet_handler(const ipacket_t *ipacket, void *args) {
    flows_t *f = (flows_t *)args;
    const mmt_session_t *session;
    const proto_hierarchy_t *hierarchy;
    flow_entry_t *e;

    if (f == NULL || ipacket == NULL) return 0;

    session = get_session_from_packet(ipacket);
    if (session == NULL) return 0;   /* no session: ARP, LLDP, ... */

    e = flow_get_or_create(f, get_session_id(session));
    if (e == NULL) return 0;         /* table full */

    if (!e->has_tuple) {
        e->has_tuple = (uint8_t)flow_fill_tuple(e, ipacket, session);
    }

    e->bytes = get_session_byte_count(session);
    e->pkts  = get_session_packet_count(session);

    /* Refreshed on every packet: the application is only known once the
     * DPI has classified enough of the session */
    hierarchy = get_session_protocol_hierarchy(session);
    if (hierarchy != NULL && hierarchy->len > 0) {
        e->app = get_application_name(hierarchy);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

flows_t *flows_create(void) {
    return (flows_t *)calloc(1, sizeof(flows_t));
}

int flows_attach(flows_t *f, mmt_handler_t *mmt) {
    /* Endpoints of a session, for both IP versions */
    static const struct {
        uint32_t proto_id;
        uint32_t attribute_id;
    } attributes[] = {
        { PROTO_IP,   IP_CLIENT_ADDR   },
        { PROTO_IP,   IP_SERVER_ADDR   },
        { PROTO_IP,   IP_CLIENT_PORT   },
        { PROTO_IP,   IP_SERVER_PORT   },
        { PROTO_IPV6, IP6_CLIENT_ADDR  },
        { PROTO_IPV6, IP6_SERVER_ADDR  },
        { PROTO_IPV6, IP6_CLIENT_PORT  },
        { PROTO_IPV6, IP6_SERVER_PORT  },
    };
    size_t i;

    if (f == NULL || mmt == NULL) return 0;

    for (i = 0; i < sizeof(attributes) / sizeof(attributes[0]); i++) {
        if (!register_extraction_attribute(mmt, attributes[i].proto_id,
                                           attributes[i].attribute_id)) {
            return 0;
        }
    }

    if (!register_packet_handler(mmt, FLOWS_PACKET_HANDLER_ID,
                                 flows_packet_handler, f)) {
        return 0;
    }

    f->mmt = mmt;
    return 1;
}

void flows_destroy(flows_t *f) {
    size_t i;

    if (f == NULL) return;

    /* Stop the DPI calling back into memory that is about to be freed */
    if (f->mmt != NULL) {
        unregister_packet_handler(f->mmt, FLOWS_PACKET_HANDLER_ID);
    }

    for (i = 0; i < FLOW_TABLE_SIZE; i++) {
        flow_entry_t *e = f->buckets[i];
        while (e != NULL) {
            flow_entry_t *next = e->next;
            free(e);
            e = next;
        }
    }
    free(f);
}

/* ------------------------------------------------------------------ */
/* Reporting                                                           */
/* ------------------------------------------------------------------ */

static int cmp_bytes_desc(const void *a, const void *b) {
    const flow_entry_t *fa = *(flow_entry_t *const *)a;
    const flow_entry_t *fb = *(flow_entry_t *const *)b;
    if (fb->bytes != fa->bytes) {
        return fb->bytes > fa->bytes ? 1 : -1;
    }
    return 0;
}

/** "10.0.0.1:443", or just the address when the protocol has no ports. */
static void endpoint_to_str(const flow_entry_t *e, int server_side,
                            char *dest, size_t dest_size) {
    char addr[INET6_ADDRSTRLEN];
    uint16_t port = server_side ? e->server_port : e->client_port;

    if (e->is_ipv6) {
        inet_ntop(AF_INET6, server_side ? e->server6 : e->client6,
                  addr, sizeof(addr));
    } else {
        struct in_addr ip;
        ip.s_addr = server_side ? e->server4 : e->client4;
        inet_ntop(AF_INET, &ip, addr, sizeof(addr));
    }

    if (port == 0) {
        snprintf(dest, dest_size, "%s", addr);
    } else if (e->is_ipv6) {
        /* Bracketed, so the port is not mistaken for another hextet */
        snprintf(dest, dest_size, "[%s]:%u", addr, port);
    } else {
        snprintf(dest, dest_size, "%s:%u", addr, port);
    }
}

void flows_print_top(flows_t *f, FILE *fp, int top_n) {
    size_t count, i;

    if (f == NULL || fp == NULL || f->nflows == 0 || top_n <= 0) return;

    /* Sessions whose endpoints never resolved (not carried over IP) are
     * not flows this report can describe */
    count = 0;
    for (i = 0; i < f->nflows; i++) {
        if (f->flows[i]->has_tuple) {
            f->flows[count++] = f->flows[i];
        }
    }
    f->nflows = count;
    if (count == 0) return;

    qsort(f->flows, count, sizeof(flow_entry_t *), cmp_bytes_desc);
    if (count > (size_t)top_n) count = (size_t)top_n;

    fprintf(fp, "\n- - - - - - TOP FLOWS BY VOLUME - - - - - -\n\n");
    fprintf(fp, "%-12s %-24s %-24s %12s %10s\n",
            "proto", "client", "server", "bytes", "pkts");

    for (i = 0; i < count; i++) {
        const flow_entry_t *e = f->flows[i];
        /* Address, two brackets, a colon and a port of up to five digits */
        char client[INET6_ADDRSTRLEN + 9], server[INET6_ADDRSTRLEN + 9];

        endpoint_to_str(e, 0, client, sizeof(client));
        endpoint_to_str(e, 1, server, sizeof(server));

        fprintf(fp, "%-12s %-24s %-24s %12" PRIu64 " %10" PRIu64 "\n",
                (e->app != NULL) ? e->app : "unknown",
                client, server, e->bytes, e->pkts);
    }
    fprintf(fp, "\n");
}
