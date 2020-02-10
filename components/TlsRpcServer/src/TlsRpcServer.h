/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosTlsApi.h"

seos_err_t
TlsRpcServer_init(
    SeosTlsRpcServer_Handle* ctx);

seos_err_t
TlsRpcServer_connect();

seos_err_t
TlsRpcServer_close();

seos_err_t
TlsRpcServer_free();