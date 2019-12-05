/*
 *  Driver ChanMUX TAP Ethernet
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "LibDebug/Debug.h"
#include "SeosError.h"
#include "seos_api_chanmux_nic_drv.h"
#include "nic_driver_common.h"
#include <camkes.h>
#include <limits.h>

//------------------------------------------------------------------------------
int chanmux_nic_driver_start(
    unsigned int channel_crtl,
    unsigned int channel_data)
{
    // can't make this "static const" or even "static" because the data ports
    // are allocated at runtime
    seos_camkes_chanmx_nic_drv_config_t config =
    {
        .notify_init_complete  = event_init_done_emit,

        .chanmux =
        {
            .ctrl =
            {
                .id            = channel_crtl,
                .port =
                {
                    .buffer    = port_chanMux_ctrl,
                    .len       = PAGE_SIZE
                }
            },
            .data =
            {
                .id            = channel_data,
                .port_read =
                {
                    .buffer    = port_chanMux_data_read,
                    .len       = PAGE_SIZE
                },
                .port_write = {
                    .buffer    = port_chanMux_data_write,
                    .len       = PAGE_SIZE
                }
            },
            .wait              = event_chanMux_hasData_wait
        },

        .network_stack =
        {
            .to = // driver -> network stack
            {
                .buffer        = port_nwStack_to,
                .len           = PAGE_SIZE
            },
            .from = // network stack -> driver
            {
                .buffer        = port_nwStack_from,
                .len           = PAGE_SIZE
            },
            .notify            = event_nwstack_hasData_emit
        }
    };

    Debug_LOG_INFO("starting network driver, ctrl=%u, data=%u",
                   config.chanmux.ctrl.id,
                   config.chanmux.data.id);

    seos_err_t ret = seos_chanmux_nic_driver_run(&config);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_FATAL("seos_chanmx_network_driver_init() failed, error %d", ret);
        return -1;
    }

    Debug_LOG_INFO("network driver main loop terminated");

    return 0;
}


//------------------------------------------------------------------------------
// CAmkES RPC API
//
// the prefix "nic_driver" is RPC connector name, the rest comes from the
// interface definition
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
seos_err_t
nic_driver_tx_data(
    size_t* pLen)
{
    return seos_chanmux_nic_driver_rpc_tx_data(pLen);
}


//------------------------------------------------------------------------------
seos_err_t
nic_driver_get_mac(void)
{
    return seos_chanmux_nic_driver_rpc_get_mac();
}
