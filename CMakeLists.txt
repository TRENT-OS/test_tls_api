cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(config/SystemConfig.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_CHANMUX
    SEOS_LIBS_LOGGER
    SEOS_NW_STACK
    SEOS_NETWORK_DRIVER_TAP_PROXY
    SEOS_CRYPTO
    SEOS_CRYPTO_IMPL_MBEDTLS
    SEOS_TLS_WITH_RPC_CLIENT
    SEOS_TLS_WITH_RPC_SERVER
    SEOS_TLS_IMPL_MBEDTLS
)

project(tests_tls_api C)

DeclareCAmkESComponent(test_OS_Tls
    INCLUDES
        config
        components/TlsRpcServer/src
    SOURCES
        components/Tests/src/test_OS_Tls.c
    C_FLAGS
        -Wall -Werror
        -DCLIENT_CONFIG=1
    LIBS
        seos_core_api
        seos_libs
        seos_crypto
        seos_network_api
        seos_tls_with_rpc_client
)

DeclareCAmkESComponent(TlsRpcServer
    INCLUDES
        config
        components/TlsRpcServer/src
    SOURCES
        components/TlsRpcServer/src/TlsRpcServer.c
    C_FLAGS
        -Wall -Werror
        # We need to ensure that when compiling this file we have set all the
        # mbedTLS defines set when compiling the TLS library. The reason for this
        # is that it pulls in mbedTLS structs on its own and these need to match
        # those in the lib.
        -DMBEDTLS_CONFIG_FILE="${SEOS_LIBS_DIR}/seos_tls/configs/MbedTLS_Config.h"
        # For NW stack
        -DCLIENT_CONFIG=1
    LIBS
        seos_core_api
        seos_libs
        seos_crypto
        seos_network_api
        seos_tls_with_rpc_server
)

DeclareCAmkESComponent(NwStack_1
    INCLUDES
        config
    SOURCES
        components/NwStack/src/network_stack.c
    C_FLAGS
        -Wall -Werror
        -DSEOS_NWSTACK_AS_CLIENT
        -DCFG_ETH_ADDR=ETH_1_ADDR
        -DCFG_ETH_GATEWAY_ADDR=ETH_1_GATEWAY_ADDR
        -DCFG_ETH_SUBNET_MASK=ETH_1_SUBNET_MASK
    LIBS
        seos_core_api
        seos_libs
        seos_nw_lib
)

DeclareCAmkESComponent(NwDriver_1
    SOURCES
        components/NwDriver/src/nic_driver.c
    C_FLAGS
        -Wall -Werror
        -DCFG_CHANMUX_CHANNEL_CRTL=CHANMUX_CHANNEL_NIC_1_CTRL
        -DCFG_CHANMUX_CHANNEL_DATA=CHANMUX_CHANNEL_NIC_1_DATA
    LIBS
        seos_core_api
        seos_libs
        chanmux_client
        seos_nw_driver_tap_proxy_lib
)

DeclareCAmkESComponent(NwStack_2
    INCLUDES
        config
    SOURCES
        components/NwStack/src/network_stack.c
    C_FLAGS
        -Wall -Werror
        -DSEOS_NWSTACK_AS_CLIENT
        -DCFG_ETH_ADDR=ETH_2_ADDR
        -DCFG_ETH_GATEWAY_ADDR=ETH_2_GATEWAY_ADDR
        -DCFG_ETH_SUBNET_MASK=ETH_2_SUBNET_MASK
    LIBS
        seos_core_api
        seos_libs
        seos_nw_lib
)

DeclareCAmkESComponent(NwDriver_2
    INCLUDES
        config
    SOURCES
        components/NwDriver/src/nic_driver.c
    C_FLAGS
        -Wall -Werror
        -DCFG_CHANMUX_CHANNEL_CRTL=CHANMUX_CHANNEL_NIC_2_CTRL
        -DCFG_CHANMUX_CHANNEL_DATA=CHANMUX_CHANNEL_NIC_2_DATA
    LIBS
        seos_core_api
        seos_libs
        chanmux_client
        seos_nw_driver_tap_proxy_lib
)

DeclareCAmkESComponent(ChanMux
    INCLUDES
        config
    SOURCES
        components/ChanMux/src/ChanMux.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_core_api
        seos_libs
        chanmux_server
)

DeclareCAmkESComponent(UartDrv
    SOURCES
        components/UART/src/UartDrv.c
        components/UART/src/qemu_uart.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_libs
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

DeclareCAmkESRootserver(main.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()
