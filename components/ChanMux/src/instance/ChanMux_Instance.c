/*
 *  WAN/LAN/NetworkStack Channel MUX
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */


#include "system_config.h"

#include "SeosError.h"
#include "assert.h"
#include <camkes.h>

#define NO_CHANMUX_FIFO         { .buffer = NULL, .len = 0 }
#define NO_CHANMUX_DATA_PORT    { .io = NULL, .len = 0 }


static uint8_t nwFifoBuf[PAGE_SIZE];
static uint8_t nwCtrFifoBuf[128];

static uint8_t nwFifoBuf_2[PAGE_SIZE];
static uint8_t nwCtrFifoBuf_2[128];

static const ChanMuxConfig_t cfgChanMux =
{
    .numChannels = CHANMUX_NUM_CHANNELS,
    .outputDataport = {
        .io  = (void**) &outputDataPort,
        .len = PAGE_SIZE
    },
    .channelsFifos = {
        NO_CHANMUX_FIFO,
        NO_CHANMUX_FIFO,
        NO_CHANMUX_FIFO,
        NO_CHANMUX_FIFO,
        { .buffer = nwCtrFifoBuf,   .len = sizeof(nwCtrFifoBuf) },
        { .buffer = nwFifoBuf,      .len = sizeof(nwFifoBuf) },
        NO_CHANMUX_FIFO,
        { .buffer = nwCtrFifoBuf_2, .len = sizeof(nwCtrFifoBuf_2) },
        { .buffer = nwFifoBuf_2,    .len = sizeof(nwFifoBuf_2) }
    }
};


typedef struct {
    ChannelDataport_t  read;
    ChannelDataport_t  write;
} dataport_rw_t;

#define CHANMUX_DATA_PORT( _pBuf_, _len_ )     { .io = _pBuf_, .len = _len_ }

#define CHANMUX_DATA_PORT_RW_SHARED(_pBuf_, _len_) \
    { \
        .read = CHANMUX_DATA_PORT(_pBuf_, _len_), \
        .write = CHANMUX_DATA_PORT(_pBuf_, _len_) \
    }

#define NO_CHANMUX_DATA_PORT_RW     CHANMUX_DATA_PORT_RW_SHARED(NULL, 0)


static const dataport_rw_t dataports[] =
{
    NO_CHANMUX_DATA_PORT_RW,
    NO_CHANMUX_DATA_PORT_RW,
    NO_CHANMUX_DATA_PORT_RW,
    NO_CHANMUX_DATA_PORT_RW,
    CHANMUX_DATA_PORT_RW_SHARED( (void**)&port_nic_1_ctrl, PAGE_SIZE ),
    {
        .read  = CHANMUX_DATA_PORT( (void**)&port_nic_1_data_read,  PAGE_SIZE ),
        .write = CHANMUX_DATA_PORT( (void**)&port_nic_1_data_write, PAGE_SIZE )
    },
    NO_CHANMUX_DATA_PORT_RW,
    CHANMUX_DATA_PORT_RW_SHARED( (void**)&port_nic_2_ctrl, PAGE_SIZE ),
    {
        .read  = CHANMUX_DATA_PORT( (void**) &port_nic_2_data_read,  PAGE_SIZE ),
        .write = CHANMUX_DATA_PORT( (void**) &port_nic_2_data_write, PAGE_SIZE )
    }
};


//------------------------------------------------------------------------------
const ChanMuxConfig_t*
ChanMux_config_getConfig(void)
{
    return &cfgChanMux;
}


//------------------------------------------------------------------------------
void
ChanMux_dataAvailable_emit(
    unsigned int chanNum)
{
    switch (chanNum)
    {
    //---------------------------------
    case CHANNEL_NW_STACK_DATA:
    case CHANNEL_NW_STACK_CTRL:
        event_nic_1_hasData_emit();
        break;

    //---------------------------------
    case CHANNEL_NW_STACK_DATA_2:
    case CHANNEL_NW_STACK_CTRL_2:
        event_nic_2_hasData_emit();
        break;


    //---------------------------------
    default:
        Debug_LOG_ERROR("%s(): invalid channel %u", __func__, chanNum);

        break;
    }
}


//------------------------------------------------------------------------------
static ChanMux*
ChanMux_getInstance(void)
{
    // singleton
    static ChanMux theOne;
    static ChanMux* self = NULL;
    static Channel_t channels[CHANMUX_NUM_CHANNELS];

    if ((NULL == self) && ChanMux_ctor(&theOne,
                                       channels,
                                       ChanMux_config_getConfig(),
                                       NULL,
                                       ChanMux_dataAvailable_emit,
                                       Output_write))
    {
        self = &theOne;
    }

    return self;
}


void
ChanMuxOut_takeByte(
    char byte)
{
    ChanMux_takeByte(ChanMux_getInstance(), byte);
}



//==============================================================================
// CAmkES Interface
//==============================================================================

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
seos_err_t
ChanMux_driver_write(
    unsigned int chanNum,
    size_t       len,
    size_t*      lenWritten)
{
    Debug_LOG_TRACE("%s(): channel %u, len %u", __func__, chanNum, len);

    // set defaults
    *lenWritten = 0;

    const ChannelDataport_t* dp = NULL;
    switch (chanNum)
    {
    //---------------------------------
    case CHANNEL_NW_STACK_DATA:
    case CHANNEL_NW_STACK_CTRL:
    case CHANNEL_NW_STACK_DATA_2:
    case CHANNEL_NW_STACK_CTRL_2:

        dp = &dataports[chanNum].write;
        break;
    //---------------------------------
    default:
        Debug_LOG_ERROR("%s(): invalid channel %u", __func__, chanNum);
        return SEOS_ERROR_ACCESS_DENIED;
    }

    Debug_ASSERT( NULL != dp );
    seos_err_t ret = ChanMux_write(ChanMux_getInstance(), chanNum, dp, &len);
    *lenWritten = len;

    Debug_LOG_TRACE("%s(): channel %u, lenWritten %u", __func__, chanNum, len);

    return ret;
}


//------------------------------------------------------------------------------
seos_err_t
ChanMux_driver_read(
    unsigned int chanNum,
    size_t       len,
    size_t*      lenRead)
{
    Debug_LOG_TRACE("%s(): channel %u, len %u", __func__, chanNum, len);

    // set defaults
    *lenRead = 0;

    const ChannelDataport_t* dp = NULL;
    switch (chanNum)
    {
    //---------------------------------
    case CHANNEL_NW_STACK_DATA:
    case CHANNEL_NW_STACK_CTRL:
    case CHANNEL_NW_STACK_DATA_2:
    case CHANNEL_NW_STACK_CTRL_2:
        dp = &dataports[chanNum].read;
        break;
    //---------------------------------
    default:
        Debug_LOG_ERROR("%s(): invalid channel %u", __func__, chanNum);
        return SEOS_ERROR_ACCESS_DENIED;
    }

    Debug_ASSERT( NULL != dp );
    seos_err_t ret = ChanMux_read(ChanMux_getInstance(), chanNum, dp, &len);
    *lenRead = len;

    Debug_LOG_TRACE("%s(): channel %u, lenRead %u", __func__, chanNum, len);

    return ret;
}
