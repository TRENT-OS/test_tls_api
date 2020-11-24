#
# Test TLS API
#
# Copyright (C) 2019-2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

os_set_config_file(
    config/SystemConfig.h
    CONFIG_PROJECT_NAME system_config)


#-------------------------------------------------------------------------------
project(tests_tls_api C)

DeclareCAmkESComponent(
    test_OS_Tls
    SOURCES
        components/Tests/src/test_OS_Tls.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        system_config
        os_core_api
        os_libs
        os_crypto
        os_network_api
        os_tls
)

DeclareCAmkESComponent(
    NwStack1
    SOURCES
        components/NwStack/src/network_stack.c
    C_FLAGS
        -Wall
        -Werror
        -DOS_NWSTACK_AS_CLIENT
        -DCFG_ETH_ADDR=ETH_1_ADDR
        -DCFG_ETH_GATEWAY_ADDR=ETH_1_GATEWAY_ADDR
        -DCFG_ETH_SUBNET_MASK=ETH_1_SUBNET_MASK
    LIBS
        system_config
        os_core_api
        os_libs
        os_network_lib
        TimeServer_client
)

DeclareCAmkESComponent_NIC_ChanMux(
    NwDriver1
    CHANMUX_CHANNEL_NIC_1_CTRL
    CHANMUX_CHANNEL_NIC_1_DATA
)

ChanMux_UART_DeclareCAmkESComponents(
    ChanMux_UART
    components/ChanMux/ChanMux_config.c
    system_config
)

DeclareCAmkESComponent(
    Ticker
    SOURCES
        components/Ticker/Ticker.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        os_core_api
        os_libs
)

TimeServer_DeclareCAmkESComponent(
    TimeServer
)

EntropySource_DeclareCAmkESComponent(
    EntropySource
)

DeclareAndCreateCamkESSystem(main.camkes)
GenerateSimulateScript()
