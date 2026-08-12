/**
 * capture.c — PCAP capture implementation
 */
#include <stdio.h>
#include <pcap.h>
#include "capture.h"
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

pcap_t *capture_init(const char *iname, uint16_t buffer_size, uint16_t snaplen) {
    pcap_t *my_pcap;
    char errbuf[1024];

    my_pcap = pcap_create(iname, errbuf);
    if (my_pcap == NULL) {
        fprintf(stderr, "[error] Couldn't open device %s: %s\n", iname, errbuf);
        return NULL;
    }

    pcap_set_snaplen(my_pcap, snaplen);
    pcap_set_promisc(my_pcap, 1);
    pcap_set_timeout(my_pcap, 0);
    pcap_set_buffer_size(my_pcap, buffer_size * 1000 * 1000);
    pcap_activate(my_pcap);

    if (pcap_datalink(my_pcap) != DLT_EN10MB) {
        fprintf(stderr, "[error] %s is not an Ethernet (Make sure you run with administrator permission!)\n", iname);
        pcap_close(my_pcap);
        return NULL;
    }

    return my_pcap;
}

void capture_callback(u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data) {
    mmt_handler_t *mmt = (mmt_handler_t *)user;
    struct pkthdr header;

    header.ts = p_pkthdr->ts;
    header.caplen = p_pkthdr->caplen;
    header.len = p_pkthdr->len;

    if (!packet_process(mmt, &header, data)) {
        fprintf(stderr, "Packet data extraction failure.\n");
    }
}
