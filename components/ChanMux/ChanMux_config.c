/*
 *  ChanMux
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SystemConfig.h"
#include "ChanMux/ChanMux.h"
#include <camkes.h>


//------------------------------------------------------------------------------
static unsigned int
resolveChannel(
    unsigned int  sender_id,
    unsigned int  chanNum_local)
{
    // ToDo: this function is supposed to map a "local" channel number passed
    //       by a sender to a "global" channel number used by the Proxy. Goal
    //       is, that only ChanMUX is aware of the global channel number that
    //       the proxy needs. All components should just use local channel
    //       numbers.
    //       Unfortunately, the NIC protocol needs to be changed first, because
    //       is still uses global channel numbers in the NIC_OPEN command. This
    //       is a legacy from the time there the control channel was shared for
    //       multiple NICs, we do not plan to use this any longer.
    //       For now this function does not implement any mapping, but it does
    //       some access control at least. Component can only use their channel
    //       numbers. We do not look into the protocol, thus rough NIC drivers
    //       may still use anything in the NIC_OPEN command

    switch (sender_id)
    {
    //----------------------------------
    case CHANMUX_ID_NIC_1:
        switch (chanNum_local)
        {
        //----------------------------------
        case CHANMUX_CHANNEL_NIC_1_CTRL: // ToDo: use local channel number
            return CHANMUX_CHANNEL_NIC_1_CTRL;
        //----------------------------------
        case CHANMUX_CHANNEL_NIC_1_DATA: // ToDo: use local channel number
            return CHANMUX_CHANNEL_NIC_1_DATA;
        //----------------------------------
        default:
            break;
        }
        break;
    //----------------------------------
    case CHANMUX_ID_NIC_2:
        switch (chanNum_local)
        {
        //----------------------------------
        case CHANMUX_CHANNEL_NIC_2_CTRL: // ToDo: use local channel number
            return CHANMUX_CHANNEL_NIC_2_CTRL;
        //----------------------------------
        case CHANMUX_CHANNEL_NIC_2_DATA: // ToDo: use local channel number
            return CHANMUX_CHANNEL_NIC_2_DATA;
        //----------------------------------
        default:
            break;
        }
        break;
    //----------------------------------
    default:
        break;
    }

    return INVALID_CHANNEL;
}


//------------------------------------------------------------------------------

static struct {
    uint8_t ctrl[128];
    // FIFO is big enough to store 1 minute of network "background" traffic.
    // Value found by manual testing, may differ in less noisy networks
    uint8_t data[1024 * PAGE_SIZE];
} nic_fifo[2];

static struct {
    ChanMux_channel_t ctrl;
    ChanMux_channel_t data;
} nic_channel[2];


#define CHANNEL_CTX_NIC_CTRL(_id_ , _idx_, _dataport_, _event_) \
    CHANMUX_CHANNEL_CTX( \
        _id_, \
        &(nic_channel[_idx_].ctrl), \
        nic_fifo[_idx_].ctrl, /* must be the buffer and not a pointer */ \
        CHANMUX_DATAPORT_DUPLEX_SHARED_ASSIGN(_dataport_), \
        _event_ \
    )


#define CHANNEL_CTX_NIC_DATA(_id_ , _idx_, _dataport_r_, _dataport_w_, _event_) \
    CHANMUX_CHANNEL_CTX( \
        _id_, \
        &(nic_channel[_idx_].data), \
        nic_fifo[_idx_].data, /* must be the buffer and not a pointer */ \
        CHANMUX_DATAPORT_DUPLEX_ASSIGN(_dataport_r_, _dataport_w_), \
        _event_ \
    )

#define CHANNELS_CTX_NIC_CTRL_DATA(_id_ctrl_, _id_data_, _idx_, _dataport_ctrl, _dataport_data_r_, _dataport_data_w_, _event_) \
    CHANNEL_CTX_NIC_CTRL(_id_ctrl_, _idx_, _dataport_ctrl, _event_), \
    CHANNEL_CTX_NIC_DATA(_id_data_, _idx_, _dataport_data_r_, _dataport_data_w_, _event_)


//------------------------------------------------------------------------------
static const ChanMux_channel_ctx_t channelCtx[] = {

    CHANNELS_CTX_NIC_CTRL_DATA(
        CHANMUX_CHANNEL_NIC_1_CTRL,
        CHANMUX_CHANNEL_NIC_1_DATA,
        0,
        nic_1_port_ctrl,
        nic_1_port_data_read,
        nic_1_port_data_write,
        nic_1_event_hasData_emit),

    CHANNELS_CTX_NIC_CTRL_DATA(
        CHANMUX_CHANNEL_NIC_2_CTRL,
        CHANMUX_CHANNEL_NIC_2_DATA,
        1,
        nic_2_port_ctrl,
        nic_2_port_data_read,
        nic_2_port_data_write,
        nic_2_event_hasData_emit)

};


//------------------------------------------------------------------------------
// this is used by the ChanMux component
const ChanMux_config_t cfgChanMux =
{
    .resolveChannel = &resolveChannel,
    .numChannels    = ARRAY_SIZE(channelCtx),
    .channelCtx     = channelCtx
};
