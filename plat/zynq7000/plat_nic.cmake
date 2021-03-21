#
# zynq7000 QEMU configuration
#
# Copyright (C) 2021, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.17)

ChanMux_UART_DeclareCAmkESComponents(
    ChanMux_UART
    components/ChanMux/ChanMux_config.c
    system_config
)

NIC_ChanMux_DeclareCAmkESComponent(
    NwDriver
    CHANMUX_CHANNEL_NIC_CTRL
    CHANMUX_CHANNEL_NIC_DATA
)
