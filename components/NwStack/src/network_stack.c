/*
 *  SEOS Network Stack CAmkES wrapper
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "SystemConfig.h"

#include "LibDebug/Debug.h"
#include "SeosError.h"
#include "seos_api_network_stack.h"
#include <camkes.h>


static const seos_network_stack_config_t config =
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
    seos_camkes_network_stack_config_t camkes_config =
    {
        .notify_init_done        = event_network_init_done_emit,
        .wait_loop_event         = event_tick_or_data_wait,

        .internal =
        {
            .notify_loop        = event_internal_emit,

            .notify_write       = e_write_emit,
            .wait_write         = c_write_wait,

            .notify_read        = e_read_emit,
            .wait_read          = c_read_wait,

            .notify_connection  = e_conn_emit,
            .wait_connection    = c_conn_wait,
        },

        .drv_nic =
        {
            .wait_init_done     = event_nic_init_done_wait,

            .from = // NIC -> stack
            {
                .buffer         = port_nic_from,
                .len            = PAGE_SIZE
            },

            .to = // stack -> NIC
            {
                .buffer         = port_nic_to,
                .len            = PAGE_SIZE
            },

            .rpc =
            {
                .dev_write      = nic_driver_tx_data,
                .get_mac        = nic_driver_get_mac,
            }
        },

        .app =
        {
            .notify_init_done   = event_network_init_done_emit,

            .port =
            {
                .buffer         = port_app_io,
                .len            = PAGE_SIZE
            },
        }
    };

    seos_err_t ret = seos_network_stack_run(&camkes_config, &config);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_FATAL("[NwStack '%s'] seos_network_stack_run() failed, error %d",
                        get_instance_name(), ret);
        return -1;
    }

    // actually, seos_network_stack_run() is not supposed to return with
    // SEOS_SUCCESS. We have to assume this is a graceful shutdown for some
    // reason
    Debug_LOG_WARNING("[NwStack '%s'] graceful termination",
                        get_instance_name());

    return 0;
}
