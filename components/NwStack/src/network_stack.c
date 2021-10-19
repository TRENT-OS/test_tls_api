/*
 * Network Stack CAmkES wrapper
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "SystemConfig.h"

#include "lib_debug/Debug.h"
#include "OS_Error.h"
#include "OS_Dataport.h"
#include "OS_NetworkStack.h"
#include "TimeServer.h"
#include <camkes.h>


static const OS_NetworkStack_AddressConfig_t config =
{
    .dev_addr      = CFG_ETH_ADDR,
    .gateway_addr  = CFG_ETH_GATEWAY_ADDR,
    .subnet_mask   = CFG_ETH_SUBNET_MASK
};

static const if_OS_Timer_t timer =
    IF_OS_TIMER_ASSIGN(
        timeServer_rpc,
        timeServer_notify);

static bool initSuccessfullyCompleted = false;

//------------------------------------------------------------------------------
// network stack's PicTCP OS adaption layer calls this.
uint64_t
Timer_getTimeMs(void)
{
    OS_Error_t err;
    uint64_t ms;

    if ((err = TimeServer_getTime(&timer, TimeServer_PRECISION_MSEC,
                                  &ms)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("TimeServer_getTime() failed with %d", err);
        ms = 0;
    }

    return ms;
}

//------------------------------------------------------------------------------
void post_init(void)
{
    Debug_LOG_INFO("[NwStack '%s'] starting", get_instance_name());

    static OS_NetworkStack_SocketResources_t socks[1] =
    {
        {
            .notify_write       = e_write_1_emit,
            .wait_write         = c_write_1_wait,

            .notify_read        = e_read_1_emit,
            .wait_read          = c_read_1_wait,

            .notify_connection  = e_conn_1_emit,
            .wait_connection    = c_conn_1_wait,

            .buf = OS_DATAPORT_ASSIGN(socket_1_port)
        }
    };

    static const NetworkStack_CamkesConfig_t camkes_config =
    {
        .wait_loop_event         = event_tick_or_data_wait,

        .internal =
        {
            .notify_loop        = event_internal_emit,

            .socketCB_lock      = socketControlBlockMutex_lock,
            .socketCB_unlock    = socketControlBlockMutex_unlock,

            .stackTS_lock       = stackThreadSafeMutex_lock,
            .stackTS_unlock     = stackThreadSafeMutex_unlock,

            .number_of_sockets  = ARRAY_SIZE(socks),
            .sockets            = socks
        },

        .drv_nic =
        {
            // NIC -> Stack
            .from =
            {
                .io = (void**)( &(nic_from_port)),
                .size = NIC_DRIVER_RINGBUFFER_NUMBER_ELEMENTS
            },
            // Stack -> NIC
            .to = OS_DATAPORT_ASSIGN(nic_to_port),

            .rpc =
            {
                .dev_read       = nic_rpc_rx_data,
                .dev_write      = nic_rpc_tx_data,
                .get_mac        = nic_rpc_get_mac_address,
            }
        },
    };

    OS_Error_t ret = NetworkStack_init(&camkes_config, &config);
    if (ret != OS_SUCCESS)
    {
        Debug_LOG_FATAL("[NwStack '%s'] NetworkStack_init() failed, error %d",
                        get_instance_name(), ret);
        return;
    }

    initSuccessfullyCompleted = true;
}


//------------------------------------------------------------------------------
int run(void)
{
    if (!initSuccessfullyCompleted)
    {
        Debug_LOG_FATAL("[NwStack '%s'] initialization failed",
                        get_instance_name());
        return -1;
    }

    OS_Error_t ret = NetworkStack_run();
    if (ret != OS_SUCCESS)
    {
        Debug_LOG_FATAL("[NwStack '%s'] NetworkStack_run() failed, error %d",
                        get_instance_name(), ret);
        return -1;
    }

    // actually, NetworkStack_run() is not supposed to return with
    // OS_SUCCESS. We have to assume this is a graceful shutdown for some
    // reason
    Debug_LOG_WARNING("[NwStack '%s'] graceful termination",
                      get_instance_name());

    return 0;
}
