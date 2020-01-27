/*
 *  Network Driver #1
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "system_config.h"

#include "LibDebug/Debug.h"
#include "nic_driver_common.h"
#include <camkes.h>

#define SEOS_TAP1_CTRL_CHANNEL          CHANNEL_NW_STACK_CTRL_2
#define SEOS_TAP1_DATA_CHANNEL          CHANNEL_NW_STACK_DATA_2

int run()
{
    Debug_LOG_INFO("starting network driver #2");

    int ret = chanmux_nic_driver_start(SEOS_TAP1_CTRL_CHANNEL,
                                       SEOS_TAP1_DATA_CHANNEL);
    if (ret < 0)
    {
        Debug_LOG_ERROR("chanmux_nic_driver_start() failed for driver #2, error %d", ret);
        return -1;
    }

    // actually, the driver is not supposed to return without an error. If it
    // does, we have to assume it wants to shutdown gracefully for some reason.
    Debug_LOG_WARNING("network driver #2 terminated gracefully");

    return 0;
}
