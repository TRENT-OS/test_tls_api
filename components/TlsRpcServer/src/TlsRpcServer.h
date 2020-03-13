/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosTlsApi.h"

seos_err_t
TlsRpcServer_init(
    void);

seos_err_t
TlsRpcServer_connect(
    void);

seos_err_t
TlsRpcServer_close(
    void);

seos_err_t
TlsRpcServer_free(
    void);