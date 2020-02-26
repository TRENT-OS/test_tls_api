/*
 *  SEOS Network Stack CAmkES App for timer client
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "LibDebug/Debug.h"
#include <camkes.h>

#define MSECS_TO_SLEEP      10
#define SIGNAL_PERIOD_MS    50

static unsigned int counterMs = 0;

//------------------------------------------------------------------------------
int
run(
    void)
{
    Debug_LOG_INFO("Starting TimerClient");

    for(;;)
    {
        Timer_sleep(MSECS_TO_SLEEP);
        counterMs += MSECS_TO_SLEEP;
        if ((counterMs % SIGNAL_PERIOD_MS) == 0)
        {
            // Debug_LOG_DEBUG("sending tick");
            e_timeout_nwstacktick_1_emit();
            e_timeout_nwstacktick_2_emit();
        }
    }
    return 0;
}


//------------------------------------------------------------------------------
unsigned int
TimerClient_getTimeMs(
    void)
{
    return counterMs;
}
