#include "parser.h"
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>

#include <arpa/inet.h>

#define MBUF_COUNT 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define RING_SIZE 8192

#define RX_PORT_ID 0
#define TX_PORT_ID 1

#define LCORE1_ID 1
#define LCORE2_ID 2

#define MAX_IPS 32

static volatile bool force_quit = false;
static struct rte_ring *packet_ring = NULL;

struct statistics
{
    uint64_t received;
    uint64_t transmitted;
    uint64_t dropped_by_type;
    uint64_t dropped_by_ip_filter;
    uint64_t dropped_by_fail;
} __rte_cache_aligned;

static struct statistics stats;

static uint32_t blocked_src_ips[MAX_IPS];
static uint16_t blocked_src_ips_count = 0;

static bool reset_mac = false;

static void signal_handler(int sig_number)
{
    if (sig_number == SIGINT || sig_number == SIGTERM) {
        printf("\nSignal %d received, preparing to exit...\n", sig_number);
        force_quit = true;
    }
}

static int receiver_thread(__rte_unused void *arg)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    while (!force_quit) {
        const uint16_t buffers_received = rte_eth_rx_burst(RX_PORT_ID, 0, bufs, BURST_SIZE);
        for (uint16_t i = 0; i < buffers_received; i++) {
            if (rte_ring_enqueue(packet_ring, bufs[i]) == 0) {
                stats.received++;
            } else {
                rte_pktmbuf_free(bufs[i]);
                stats.dropped_by_fail++;
            }
        }
    }
    return 0;
}

static int transmitter_thread(__rte_unused void *arg)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    while (!force_quit) {
        unsigned packets_deqeued = rte_ring_dequeue_burst(packet_ring,
                                                          (void **) bufs,
                                                          BURST_SIZE,
                                                          NULL);
        for (unsigned i = 0; i < packets_deqeued; i++) {
            struct rte_mbuf *mbuf = bufs[i];

            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

            if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4) {
                uint32_t src_ip;
                struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *) (eth_hdr + 1);

                bool is_ip_blocked = false;
                for (uint16_t j = 0; j < blocked_src_ips_count && !is_ip_blocked; j++) {
                    if (blocked_src_ips[j] == ip_hdr->src_addr) {
                        is_ip_blocked = true;
                    }
                }

                if (is_ip_blocked) {
                    rte_pktmbuf_free(mbuf);
                    stats.dropped_by_ip_filter++;
                    continue;
                }

                if (reset_mac) {
                    struct rte_ether_addr *src = &eth_hdr->src_addr;
                    memset(src->addr_bytes, 0, RTE_ETHER_ADDR_LEN);
                }

                const uint16_t sent = rte_eth_tx_burst(1, 0, &mbuf, 1);
                if (sent > 0) {
                    stats.transmitted++;
                } else {
                    rte_pktmbuf_free(mbuf);
                    stats.dropped_by_fail++;
                }

            } else {
                rte_pktmbuf_free(mbuf);
                stats.dropped_by_type++;
                continue;
            }
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    char *blocked_ips_str = NULL;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--blocked-ips=", 14) == 0) {
            blocked_ips_str = argv[i] + 14;
        } else if (strncmp(argv[i], "--reset-mac", 11) == 0) {
            reset_mac = true;
        }
    }

    if (blocked_ips_str != NULL) {
        blocked_src_ips_count = parse_ip_list(blocked_ips_str, blocked_src_ips, MAX_IPS);
    }

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "EAL initialisation error\n");
    }

    uint16_t ports_count = rte_eth_dev_count_avail();
    if (ports_count < 2) {
        rte_exit(EXIT_FAILURE, "Minimum 2 ports are required\n");
    }

    if (rte_lcore_count() < 3) {
        rte_exit(EXIT_FAILURE, "Minimum 3 lcores are required\n");
    }

    // stop/exit signals
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                                            MBUF_COUNT * ports_count,
                                                            MBUF_CACHE_SIZE,
                                                            0,
                                                            RTE_MBUF_DEFAULT_BUF_SIZE,
                                                            rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }

    packet_ring = rte_ring_create("packet_ring",
                                  RING_SIZE,
                                  rte_socket_id(),
                                  RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (packet_ring == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create ring buffer\n");
    }

    for (uint16_t portid = 0; portid < 2; portid++) {
        struct rte_eth_conf port_conf = {0};
        rte_eth_dev_configure(portid, 1, 1, &port_conf);
        rte_eth_rx_queue_setup(portid, 0, 128, rte_eth_dev_socket_id(portid), NULL, mbuf_pool);
        rte_eth_tx_queue_setup(portid, 0, 128, rte_eth_dev_socket_id(portid), NULL);
        rte_eth_dev_start(portid);
        rte_eth_promiscuous_enable(portid);
    }

    uint16_t rx_res = rte_eal_remote_launch(receiver_thread, NULL, LCORE1_ID);
    if (rx_res < 0) {
        rte_exit(EXIT_FAILURE, "Failed to start rx task\n");
    }
    uint16_t tx_res = rte_eal_remote_launch(transmitter_thread, NULL, LCORE2_ID);
    if (tx_res < 0) {
        rte_exit(EXIT_FAILURE, "Failed to start tx task\n");
    }

    rte_eal_mp_wait_lcore();

    printf("--------- Statistics ---------\n  Received: %lu\n  Transmitted: %lu\n  Dropped by "
           "type: %lu\n  Dropped by ip filter: %lu\n  Dropped by fail: %lu\n",
           stats.received,
           stats.transmitted,
           stats.dropped_by_type,
           stats.dropped_by_ip_filter,
           stats.dropped_by_fail);

    for (uint16_t portid = 0; portid < 2; portid++) {
        rte_eth_dev_stop(portid);
    }

    return 0;
}
