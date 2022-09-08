#
# Copyright (c) 2022 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

project(wfa_dut)
cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

#set(WIFI_NRF_DRV_BASE ${WEST_TOPDIR}/nrf/drivers/wifi/nrf700x)
#if(CONFIG_WPA_SUPP)
#set(WPA_SUPP_BASE ${WEST_TOPDIR}/modules/lib/hostap)
#endif()

zephyr_library_sources_ifdef(CONFIG_WFA_DUT
	src/wfa_shell.c
	src/dut/wfa_sock.c
	src/dut/wfa_tg.c
	src/dut/wfa_cs.c
	src/dut/wfa_ca_resp.c
	src/dut/wfa_tlv.c
	src/dut/wfa_typestr.c
	src/dut/wfa_cmdtbl.c
	src/dut/wfa_cmdproc.c
	src/dut/wfa_miscs.c
	src/dut/wfa_thr.c
	src/dut/wfa_wmmps.c
	src/dut/wfa_dut_init.c
	src/dut/wfa_dut.c
	)
#target_sources(app PRIVATE
#	src/wfa_shell.c
#	src/dut/wfa_sock.c
#	src/dut/wfa_tg.c
#	src/dut/wfa_cs.c
#	src/dut/wfa_ca_resp.c
#	src/dut/wfa_tlv.c
#	src/dut/wfa_typestr.c
#	src/dut/wfa_cmdtbl.c
#	src/dut/wfa_cmdproc.c
#	src/dut/wfa_miscs.c
#	src/dut/wfa_thr.c
#	src/dut/wfa_wmmps.c
#	src/dut/wfa_dut_init.c
#	src/dut/wfa_dut.c
#)
