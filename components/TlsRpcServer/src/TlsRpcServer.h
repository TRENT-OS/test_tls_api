/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Tls.h"

OS_Error_t
TlsRpcServer_init(
    void);

OS_Error_t
TlsRpcServer_connect(
    void);

OS_Error_t
TlsRpcServer_close(
    void);

OS_Error_t
TlsRpcServer_free(
    void);