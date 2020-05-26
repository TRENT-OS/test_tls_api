/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "LibDebug/Debug.h"

#include <string.h>
#include <assert.h>

#define MAX_MSG_LEN 256

// We use this to keep track of the name of the test that is is currently being
// executed, see below...
static char testName[MAX_MSG_LEN] = "<undefined>";

/*
 * With the help of TEST_START() and TEST_FINISH() we can track which test is
 * currently running so we know the test's name in case an assertion is hit.
 *
 * TEST_START can take up to two arguments (which will be interpreted as int)
 * TEST_FINISH takes no arguments
 */

// With this trick, we can map between zero to two arguments to the respective
// "sub-macro" and use the appropriate format string.
#define SELECT_START(PREFIX,_2,_1,_0,SUFFIX,...) PREFIX ## _ ## SUFFIX
#define _TEST_START_STOP(...) \
    Debug_ASSERT_PRINTFLN(0, "Too many arguments for TEST_START.")
#define _TEST_START_2(arg0, arg1) \
    snprintf(testName, sizeof(testName), "%s(%s=%i,%s=%i)", __func__, #arg0, (int)arg0, #arg1, (int)arg1)
#define _TEST_START_1(arg0) \
    snprintf(testName, sizeof(testName), "%s(%s=%i)", __func__, #arg0, (int)arg0)
#define _TEST_START_0(...) \
    snprintf(testName, sizeof(testName), "%s", __func__)
#define TEST_START(...) \
    SELECT_START(_TEST_START, ## __VA_ARGS__,STOP,2,1,0)(__VA_ARGS__)
// This outputs the tests name as a marker that it has been completed. Also, we
// reset the testName to make incorrect use of TEST_START/TEST_FINISH more easy
// to spot.
#define TEST_FINISH() {                                     \
    Debug_LOG_INFO("!!! %s: OK", testName);                 \
    snprintf(testName, sizeof(testName), "<undefined>");    \
}

/**
 * With the help of these TEST_xxx we obtain practical shorthands for checking
 * a function result agains OS_Error_t error codes.
 *
 * Furthermore (and more importantly), we can define and use our own assertions,
 * so that we can add the name of the test to a failing assertion. This is useful
 * if the assert does not fail in the test function itself, but in a function
 * called by the test (in this case, assert does not give the test function name
 * but the name of the subfunction).
 */

// Assert to check for a specific error code
// Checking return value of snprintf to stop GCC from throwing error about 
// format truncation.
#define ASSERT_ERR(x, err) {                                                        \
    char msg[MAX_MSG_LEN];                                                          \
    int ret = snprintf(msg, sizeof(msg), "@%s: %s == %s", testName, #x, #err);      \
    if(ret>=sizeof(msg)) { /*Message was truncated */};                             \
    ((void)(((x) == err) || (__assert_fail(msg, __FILE__, __LINE__, __func__),0))); \
}
// These shorthands can be used to simply check function return codes
#define TEST_INSUFF_SPACE(fn) \
    ASSERT_ERR(fn, SEOS_ERROR_INSUFFICIENT_SPACE)
#define TEST_TOO_SMALL(fn) \
    ASSERT_ERR(fn, SEOS_ERROR_BUFFER_TOO_SMALL)
#define TEST_ABORTED(fn) \
    ASSERT_ERR(fn, SEOS_ERROR_ABORTED)
#define TEST_OP_DENIED(fn) \
    ASSERT_ERR(fn, SEOS_ERROR_OPERATION_DENIED)
#define TEST_ACC_DENIED(fn) \
    ASSERT_ERR(fn, SEOS_ERROR_ACCESS_DENIED)
#define TEST_NOT_FOUND(fn) \
    ASSERT_ERR(fn, SEOS_ERROR_NOT_FOUND)
#define TEST_INVAL_HANDLE(fn) \
    ASSERT_ERR(fn, SEOS_ERROR_INVALID_HANDLE)
#define TEST_INVAL_NAME(fn) \
    ASSERT_ERR(fn, SEOS_ERROR_INVALID_NAME)
#define TEST_INVAL_PARAM(fn) \
    ASSERT_ERR(fn, SEOS_ERROR_INVALID_PARAMETER)
#define TEST_NOT_SUPP(fn) \
    ASSERT_ERR(fn, SEOS_ERROR_NOT_SUPPORTED)
#define TEST_GENERIC(fn) \
    ASSERT_ERR(fn, SEOS_ERROR_GENERIC)
#define TEST_SUCCESS(fn) \
    ASSERT_ERR(fn, SEOS_SUCCESS)
// Check boolean expression and not an error code
// Checking return value of snprintf to stop GCC from throwing error about 
// format truncation.
#define TEST_TRUE(st) {                                                      \
    char msg[MAX_MSG_LEN];                                                   \
    int ret = snprintf(msg, sizeof(msg), "@%s: %s", testName, #st);          \
    if(ret>=sizeof(msg)) { /*Message was truncated */};                      \
    ((void)((st) || (__assert_fail(msg, __FILE__, __LINE__, __func__),0)));  \
}
