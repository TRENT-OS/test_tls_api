/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "LibDebug/Debug.h"

/**
 * The TEST_OK macro allows to produce a recognaizable output string after
 * test completion. This macro can handle between none and two parameters
 * thanks to a little trick.
 *
 * NOTE: Any parameter passed will be treated as integer!
 */

#define SELECT_OK(PREFIX,_2,_1,_0,SUFFIX,...) PREFIX ## _ ## SUFFIX

#define _TEST_OK_STOP(...) \
    Debug_ASSERT_PRINTFLN(0, "Too many arguments for TEST_OK, can have 0 to 2.")
#define _TEST_OK_2(arg0, arg1) \
    Debug_PRINTF("!!! %s(%s=%i,%s=%i): OK\n", __func__, #arg0, (int)arg0, #arg1, (int)arg1)
#define _TEST_OK_1(arg0) \
    Debug_PRINTF("!!! %s(%s=%i): OK\n", __func__, #arg0, (int)arg0)
#define _TEST_OK_0(...) \
    Debug_PRINTF("!!! %s: OK\n", __func__)
#define TEST_OK(...) \
    SELECT_OK(_TEST_OK, ## __VA_ARGS__,STOP,2,1,0)(__VA_ARGS__)
