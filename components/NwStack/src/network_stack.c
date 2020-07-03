/*
 *  OS Network Stack CAmkES wrapper
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "SystemConfig.h"

#include "LibDebug/Debug.h"
#include "OS_Error.h"
#include "OS_NetworkStack.h"
#include <camkes.h>


static const os_network_stack_config_t config =
{
    .dev_addr      = CFG_ETH_ADDR,
    .gateway_addr  = CFG_ETH_GATEWAY_ADDR,
    .subnet_mask   = CFG_ETH_SUBNET_MASK
};


//------------------------------------------------------------------------------
int run()
{
    Debug_LOG_INFO("[NwStack '%s'] starting", get_instance_name());

    // can't make this "static const" or even "static" because the data ports
    // are allocated at runtime
    os_camkes_network_stack_config_t camkes_config =
    {
        .notify_init_done        = event_network_init_done_emit,
        .wait_loop_event         = event_tick_or_data_wait,

        .internal =
        {
            .notify_loop        = event_internal_emit,

            .number_of_sockets  = 1,

            .socketCB_lock      = socketControlBlockMutex_lock,
            .socketCB_unlock    = socketControlBlockMutex_unlock,

            .stackTS_lock       = stackThreadSafeMutex_lock,
            .stackTS_unlock     = stackThreadSafeMutex_unlock,
        },

        .drv_nic =
        {
            // NIC -> Stack
            .from = OS_DATAPORT_ASSIGN(port_nic_from),

            // Stack -> NIC
            .to = OS_DATAPORT_ASSIGN(port_nic_to),

            .rpc =
            {
                .dev_write      = nic_driver_tx_data,
                .get_mac        = nic_driver_get_mac,
            }
        },

        .app =
        {
            .notify_init_done   = event_network_init_done_emit,
        }
    };

    static os_network_socket_t socks = {
                .notify_write       = e_write_emit,
                .wait_write         = c_write_wait,

                .notify_read        = e_read_emit,
                .wait_read          = c_read_wait,

                .notify_connection  = e_conn_emit,
                .wait_connection    = c_conn_wait,

                .buf = OS_DATAPORT_ASSIGN(port_app_io)
            };

    camkes_config.internal.number_of_sockets = 1;
    camkes_config.internal.sockets = &socks;

    OS_Error_t ret = OS_NetworkStack_run(&camkes_config, &config);
    if (ret != OS_SUCCESS)
    {
        Debug_LOG_FATAL("[NwStack '%s'] OS_NetworkStack_run() failed, error %d",
                        get_instance_name(), ret);
        return -1;
    }

    // actually, OS_NetworkStack_run() is not supposed to return with
    // OS_SUCCESS. We have to assume this is a graceful shutdown for some
    // reason
    Debug_LOG_WARNING("[NwStack '%s'] graceful termination",
                        get_instance_name());

    return 0;
}
