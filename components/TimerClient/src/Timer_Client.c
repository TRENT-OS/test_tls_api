/*
 *  SEOS Network Stack CAmkES App for timer client
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include <stdio.h>
#include <camkes.h>

#define MSECS_TO_SLEEP      10
#define SIGNAL_PERIOD_MS    100

static unsigned counterMs = 0;

/* run the control thread */
int run(void)
{
    printf("Starting the client\n");
    printf("------Sleep for %d mseconds------\n", MSECS_TO_SLEEP);

    while (1)
    {
        Timer_sleep(MSECS_TO_SLEEP);
        counterMs += MSECS_TO_SLEEP;
        if ((counterMs % SIGNAL_PERIOD_MS) == 0)
        {
            //printf("%s: sending tick\n", __func__);
            e_timeout_nwstacktick_emit();
            e_timeout_nwstacktick_2_emit();
        }
    }
    return 0;
}

unsigned
TimerClient_getTimeMs()
{
    return counterMs;
}
