/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/* @file
 * @brief Wi-Fi shell sample
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <zephyr/zephyr.h>
#include <zephyr/shell/shell.h>
#include <zephyr/init.h>

#include <net/net_if.h>
#include <net/wifi_mgmt.h>
#include <net/net_event.h>
#include <zephyr_fmac_main.h>
#include <zephyr/random/rand32.h>


static int wfa_dut_test(const struct shell *shell,
			  size_t argc,
			  const char *argv[])
{
	printf("arg0: %s\n", argv[0]);
	return dut_main(argc,
			argv);
}

struct net_icmpv4_echo_req {
	uint16_t identifier;
	uint16_t sequence;
} __packed;

typedef enum net_verdict (*icmpv4_callback_handler_t)(
					struct net_pkt *pkt,
					struct net_ipv4_hdr *ip_hdr,
					struct net_icmp_hdr *icmp_hdr);

struct net_icmpv4_handler {
	sys_snode_t node;
	icmpv4_callback_handler_t handler;
	uint8_t type;
	uint8_t code;
};


K_SEM_DEFINE(ping4_timeout, 0, 1);


static enum net_verdict handle_ipv4_echo_reply(struct net_pkt *pkt,
					       struct net_ipv4_hdr *ip_hdr,
					       struct net_icmp_hdr *icmp_hdr)
{
	NET_PKT_DATA_ACCESS_CONTIGUOUS_DEFINE(icmp_access,
					      struct net_icmpv4_echo_req);
	uint32_t cycles;
	struct net_icmpv4_echo_req *icmp_echo;
	char saddr_buf[32] = {0};
	char daddr_buf[32] = {0};

	icmp_echo = (struct net_icmpv4_echo_req *)net_pkt_get_data(pkt,
								&icmp_access);
	if (icmp_echo == NULL) {
		return -NET_DROP;
	}

	net_pkt_skip(pkt, sizeof(*icmp_echo));
	if (net_pkt_read_be32(pkt, &cycles)) {
		return -NET_DROP;
	}

	cycles = k_cycle_get_32() - cycles;

	printf("%d bytes from %s to %s: icmp_seq=%d ttl=%d "
#ifdef CONFIG_FPU
		 "time=%.2f ms\n",
#else
		 "time=%d ms\n",
#endif
		 ntohs(ip_hdr->len) - net_pkt_ipv6_ext_len(pkt) -
								NET_ICMPH_LEN,
		 net_addr_ntop(AF_INET,
				&ip_hdr->src,
				saddr_buf, sizeof(saddr_buf)),
		  net_addr_ntop(AF_INET,
				&ip_hdr->dst,
				daddr_buf, sizeof(daddr_buf)),
		 ntohs(icmp_echo->sequence),
		 ip_hdr->ttl,
#ifdef CONFIG_FPU
		 ((uint32_t)k_cyc_to_ns_floor64(cycles) / 1000000.f));
#else
		 ((uint32_t)k_cyc_to_ns_floor64(cycles) / 1000000));
#endif
	k_sem_give(&ping4_timeout);

	net_pkt_unref(pkt);
	return NET_OK;
}

static struct net_icmpv4_handler ping4_handler = {
	.type = 0,
	.code = 0,
	.handler = handle_ipv4_echo_reply,
};

static inline void remove_ipv4_ping_handler(void)
{
	net_icmpv4_unregister_handler(&ping4_handler);
}

static int wfa_dut_send_start(const struct shell *shell,
			  size_t argc,
			  const char *argv[])
{
	printf("arg0: %s\n", argv[0]);
	unsigned char *respBuf = os_zalloc(64 * sizeof(unsigned char));
	int bufLen = 0;
#if 0
	struct in_addr ipv4_target;
	struct net_if *iface = net_if_get_default();
	int ret = 0;
	 int count = 8;
	 int interval = 1;
	 const char *host = "8.8.8.8";

	if (net_addr_pton(AF_INET, host, &ipv4_target) < 0) {
		return -EINVAL;
	}

	net_icmpv4_register_handler(&ping4_handler);

	printf("PING %s\n", host);
	for (int i = 0; i < count; ++i) {
		uint32_t time_stamp = htonl(k_cycle_get_32());

		ret = net_icmpv4_send_echo_request(iface,
						   &ipv4_target,
						   sys_rand32_get(),
						   i,
						   &time_stamp,
						   sizeof(time_stamp));
		if (ret) {
			break;
		}

		k_msleep(interval);
	}

	ret = k_sem_take(&ping4_timeout, K_SECONDS(2));
	if (ret == -EAGAIN) {
		printf("Ping timeout\n");
		remove_ipv4_ping_handler();

		return -ETIMEDOUT;
	}
#endif
	int streamid = 1;
	unsigned char streamId = streamid; 
	int status = wfaTGSendStart (4, &streamId, &bufLen, respBuf);
	return status;
}

static int wfa_dut_traffic_config(const struct shell *shell,
			  size_t argc,
			  const char *argv[])
{
	printf("arg0: %s\n", argv[0]);
	unsigned char *respBuf = os_zalloc(64 * sizeof(unsigned char));
	int bufLen = 0;
	int status = -1;
	char cmdBuf[512] = "traffic_agent_config,profile,IPTV,direction,send,destination,192.165.100.8,destinationPort,5602,sourcePort,5602,duration,10,payloadSize,100,trafficClass,BestEffort,frameRate,1";
	status = commandHandle(cmdBuf);
	//status = wfaTGConfig (strlen(cmdBuf), cmdBuf, &bufLen, respBuf);
	return status;
}
#endif /* CONFIG_WPA_SUPP */


SHELL_STATIC_SUBCMD_SET_CREATE(
	wfa_dut_cmds
	SHELL_CMD(dut_test,
		  NULL,
		  "\"\"",
		  wfa_dut_test),
	SHELL_CMD(dut_send_start,
		  NULL,
		  "\"\"",
		  wfa_dut_send_start),
	SHELL_CMD(dut_traffic_config,
		  NULL,
		  "\"\"",
		  wfa_dut_traffic_config),	  
	SHELL_SUBCMD_SET_END);

/* Persisting with "wpa_cli" naming for compatibility with Wi-Fi
 * certification applications and scripts.
 */
SHELL_CMD_REGISTER(wfa_dut,
		   &wfa_dut_cmds,
		   "WFA DUT commands",
		   NULL);


static int wifi_shell_init(const struct device *unused)
{
	ARG_UNUSED(unused);

	context.shell = NULL;
	context.all = 0U;

	return 0;
}


SYS_INIT(wifi_shell_init,
	 APPLICATION,
	 CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
