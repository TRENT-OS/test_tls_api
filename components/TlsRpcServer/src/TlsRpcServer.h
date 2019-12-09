/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosTlsApi.h"

#define SeosTlsServer_SIZE_IP   32

typedef struct {
    char    ip[SeosTlsServer_SIZE_IP];
    int     port;
} TlsRpcServer_Config;

seos_err_t
TlsRpcServer_init(SeosTlsRpcServer_Handle* ctx, TlsRpcServer_Config cfg);

seos_err_t
TlsRpcServer_free();