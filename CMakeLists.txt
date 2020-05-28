cmake_minimum_required(VERSION 3.7.2)

os_set_config_file(config/SystemConfig.h)

os_use_libs(
    OS_LIBS
    OS_CHANMUX
    OS_LIBS_LOGGER
    OS_NW_STACK
    OS_NETWORK_DRIVER_TAP_PROXY
    OS_CRYPTO
    OS_TLS_WITH_RPC_CLIENT
    OS_TLS_WITH_RPC_SERVER
)


project(system_config C)
add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE config)


project(tests_tls_api C)

DeclareCAmkESComponent(test_OS_Tls
    INCLUDES
        components/TlsRpcServer/src
    SOURCES
        components/Tests/src/test_OS_Tls.c
    C_FLAGS
        -Wall -Werror
        -DCLIENT_CONFIG=1
    LIBS
        system_config
        seos_core_api
        seos_libs
        seos_crypto
        seos_network_api
        seos_tls_with_rpc_client
)

DeclareCAmkESComponent(TlsRpcServer
    INCLUDES
        components/TlsRpcServer/src
    SOURCES
        components/TlsRpcServer/src/TlsRpcServer.c
    C_FLAGS
        -Wall -Werror
        # For NW stack
        -DCLIENT_CONFIG=1
    LIBS
        system_config
        seos_core_api
        seos_libs
        seos_crypto
        seos_network_api
        seos_tls_with_rpc_server
)

DeclareCAmkESComponent(NwStack_1
    SOURCES
        components/NwStack/src/network_stack.c
    C_FLAGS
        -Wall -Werror
        -DOS_NWSTACK_AS_CLIENT
        -DCFG_ETH_ADDR=ETH_1_ADDR
        -DCFG_ETH_GATEWAY_ADDR=ETH_1_GATEWAY_ADDR
        -DCFG_ETH_SUBNET_MASK=ETH_1_SUBNET_MASK
    LIBS
        system_config
        seos_core_api
        seos_libs
        seos_nw_lib
)

DeclareCAmkESComponent_NIC_ChanMux(
    NwDriver_1
    CHANMUX_CHANNEL_NIC_1_CTRL
    CHANMUX_CHANNEL_NIC_1_DATA
)

DeclareCAmkESComponent(NwStack_2
    SOURCES
        components/NwStack/src/network_stack.c
    C_FLAGS
        -Wall -Werror
        -DOS_NWSTACK_AS_CLIENT
        -DCFG_ETH_ADDR=ETH_2_ADDR
        -DCFG_ETH_GATEWAY_ADDR=ETH_2_GATEWAY_ADDR
        -DCFG_ETH_SUBNET_MASK=ETH_2_SUBNET_MASK
    LIBS
        system_config
        seos_core_api
        seos_libs
        seos_nw_lib
)

DeclareCAmkESComponent_NIC_ChanMux(
    NwDriver_2
    CHANMUX_CHANNEL_NIC_2_CTRL
    CHANMUX_CHANNEL_NIC_2_DATA
)

DeclareCAmkESComponent_ChanMux(
    ChanMux
    components/ChanMux/ChanMux_config.c
    system_config
)

DeclareCAmkESComponent_UART(
    UART
)

DeclareCAmkESComponent(TimerClient
    SOURCES
        components/TimerClient/src/Timer_Client.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_libs
)

DeclareCAmkESComponent(Timer
    SOURCES
        components/Timer/src/timer.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_libs
)

DeclareAndCreateCamkESSystem(main.camkes)
GenerateSimulateScript()
