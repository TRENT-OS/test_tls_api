/*
 *  Driver ChanMUX TAP Ethernet
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "LibDebug/Debug.h"
#include "SeosError.h"
#include "chanmux_nic_drv_api.h"
#include <camkes.h>
#include <limits.h>

static chanmux_nic_drv_config_t config;


//------------------------------------------------------------------------------
void
post_init(void)
{
    Debug_LOG_INFO("[NIC '%s'] %s()", get_instance_name(), __func__);

    // can't make this "static const" or even "static" because the data ports
    // are allocated at runtime
    chanmux_nic_drv_config_t my_config =
    {
        .chanmux =
        {
            .ctrl =
            {
                .id            = CFG_CHANMUX_CHANNEL_CRTL,
                .port =
                {
                    .buffer    = port_chanMux_ctrl,
                    .len       = PAGE_SIZE
                }
            },
            .data =
            {
                .id            = CFG_CHANMUX_CHANNEL_DATA,
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
            .wait              = ChanMuxSignal_dataAvailable_wait
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
        },

        .nic_control_channel_mutex =
        {
            .lock    = nic_control_channel_mutex_lock,
            .unlock  = nic_control_channel_mutex_unlock
        }
    };

    config = my_config;

    seos_err_t ret = chanmux_nic_driver_init(&config);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_FATAL("[NIC '%s'] chanmux_nic_driver_init() failed, error %d",
                        get_instance_name(), ret);
    }
}



//------------------------------------------------------------------------------
int
run(void)
{
    Debug_LOG_INFO("[NIC '%s'] %s()", get_instance_name(), __func__);

    seos_err_t ret = chanmux_nic_driver_run();
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_FATAL("[NIC '%s'] chanmux_nic_driver_run() failed, error %d",
                        get_instance_name(), ret);
        return -1;
    }

    // actually, this is not supposed to return with SEOS_SUCCESS. We have to
    // assume this is a graceful shutdown for some reason
    Debug_LOG_WARNING("[NIC '%s'] graceful termination", get_instance_name());

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
    return chanmux_nic_driver_rpc_tx_data(pLen);
}


//------------------------------------------------------------------------------
seos_err_t
nic_driver_get_mac(void)
{
    return chanmux_nic_driver_rpc_get_mac();
}
