/*
 *  WAN/LAN/NetworkStack Channel MUX
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */


#include "ChanMux/ChanMux.h"
#include "ChanMux_config.h"
#include "SeosError.h"
#include "assert.h"
#include <camkes.h>

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
        {
            // Channel 0
            .buffer = NULL,
            .len = 0,
        },
        {
            // Channel 1
            .buffer = NULL,
            .len = 0,
        },
        {
            // Channel 2
            .buffer = NULL,
            .len = 0,
        },
        {
            // Channel 3
            .buffer = NULL,
            .len = 0,
        },
        {
            // Channel 4
            .buffer = nwCtrFifoBuf,
            .len = sizeof(nwCtrFifoBuf)
        },
        {
            // Channel 5
            .buffer = nwFifoBuf,
            .len = sizeof(nwFifoBuf)

        },

        {
            // Channel 6
            .buffer = NULL,
            .len = 0,
        },

        {
            //channel 7
            .buffer = nwCtrFifoBuf_2,
            .len = sizeof(nwCtrFifoBuf_2)

        },

        {
            //channel 8
            .buffer = nwFifoBuf_2,
            .len = sizeof(nwFifoBuf_2)
        }

    }
};


const ChannelDataport_t dataports[] =
{
    {
        .io = NULL,
        .len = PAGE_SIZE
    },
    {
        .io = NULL,
        .len = PAGE_SIZE
    },
    {
        .io = NULL,
        .len = PAGE_SIZE
    },
    {
        .io = NULL,
        .len = PAGE_SIZE
    },
    {
        .io = (void**) &nwStackCtrlDataPort,
        .len = PAGE_SIZE
    },
    {
        .io = (void**) &nwStackDataPort,
        .len = PAGE_SIZE
    },
    {
        .io  = NULL,
        .len = PAGE_SIZE
    },

    {
        .io  = (void**) &nwStackCtrlDataPort_2,
        .len = PAGE_SIZE
    },

    {
        .io  = (void**) &nwStackDataPort_2,
        .len = PAGE_SIZE
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
    //---------------------------------
    case CHANNEL_NW_STACK_DATA:
    case CHANNEL_NW_STACK_CTRL:
        e_read_nwstacktick_emit();
        break;

    //---------------------------------
    case CHANNEL_NW_STACK_DATA_2:
    case CHANNEL_NW_STACK_CTRL_2:
        e_read_nwstacktick_2_emit();
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
    static ChanMux  theOne;
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
ChanMuxOut_takeByte(char byte)
{
    ChanMux_takeByte(ChanMux_getInstance(), byte);
}



//==============================================================================
// CAmkES Interface
//==============================================================================

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
seos_err_t
ChanMuxNwStack_write(
    unsigned int  chanNum,
    size_t        len,
    size_t*       lenWritten)
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

        dp = &dataports[chanNum];
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
ChanMuxNwStack_read(
    unsigned int  chanNum,
    size_t        len,
    size_t*       lenRead)
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
        dp = &dataports[chanNum];
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
