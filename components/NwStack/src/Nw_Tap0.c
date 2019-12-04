/*
 *  SEOS Network Stack CAmkES wrapper
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include <camkes.h>
#include <string.h>

#include "LibDebug/Debug.h"
#include "SeosNwStack.h"
#include "ChanMux_config.h"
#include "Seos_Driver_Config.h"

#define SEOS_TAP0_CTRL_CHANNEL          CHANNEL_NW_STACK_CTRL
#define SEOS_TAP0_DATA_CHANNEL          CHANNEL_NW_STACK_DATA

#define SEOS_TAP0_ADDR                  "192.168.82.138"
#define SEOS_TAP0_GATEWAY_ADDR          "192.168.82.1"
#define SEOS_TAP0_SUBNET_MASK           "255.255.255.0"

int run()
{
    Debug_LOG_INFO("starting network stack as Client...\n");
    int ret;
    seos_nw_camkes_signal_glue nw_signal =
    {
        .e_write_emit        =  e_write_emit,
        .c_write_wait        =  c_write_wait,
        .e_read_emit         =  e_read_emit,
        .c_read_wait         =  c_read_wait,
        .e_conn_emit         =  NULL,
        .c_conn_wait         =  NULL,
        .e_write_nwstacktick =  e_write_nwstacktick_emit,
        .c_nwstacktick_wait  =  c_nwstacktick_wait,
        .e_initdone          =  e_initdone_emit,
        .c_initdone          =  c_initdone_wait
    };
    seos_nw_ports_glue nw_data =
    {
        .ChanMuxDataPort     =  chanMuxDataPort,
        .ChanMuxCtrlPort     =  chanMuxCtrlDataPort,
        .Appdataport         =  NwAppDataPort
    };

    /* First init Nw driver and then init Nw stack. Driver fills the device
     * create callback
     */
    seos_driver_config nw_driver_config_client =
    {
        .chan_ctrl              = SEOS_TAP0_CTRL_CHANNEL,
        .chan_data              = SEOS_TAP0_DATA_CHANNEL,
        .device_create_callback = NULL
    };

    ret = Seos_NwDriver_init(&nw_driver_config_client);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_FATAL("%s():Nw Driver Tap Config Failed for Client!", __FUNCTION__);
        exit(0);
    }

    seos_nw_config nw_stack_config =
    {
        .dev_addr               = SEOS_TAP0_ADDR,
        .gateway_addr           = SEOS_TAP0_GATEWAY_ADDR,
        .subnet_mask            = SEOS_TAP0_SUBNET_MASK,
        .driver_create_device   = nw_driver_config_client.device_create_callback
    };
    Seos_nw_camkes_info nw_camkes =
    {
        &nw_signal,
        &nw_data,
    };

    ret = Seos_NwStack_init(&nw_camkes, &nw_stack_config);

    /* is possible when proxy does not run with tap =1 param. Just print and exit*/
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_WARNING("Network Stack Init() Failed as Client...Exiting NwStack. Error:%d\n",
                          ret);
    }
    return 0;
}
