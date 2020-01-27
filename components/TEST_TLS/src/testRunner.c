/**
 * @addtogroup TlsApi_Tests
 * @{
 *
 * @file testRunner.c
 *
 * @brief Top level test for the TLS API
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"
#include "SeosTlsApi.h"

#include "test_config.h"

#include "LibDebug/Debug.h"

#include "TlsRpcServer.h"

#include "SeosError.h"
#include "seos_nw_api.h"

#include <camkes.h>
#include <string.h>

#define MAX_NW_SIZE 2048

extern seos_err_t Seos_NwAPP_RT(
    Seos_nw_context ctx);

static int
sendFunc(
    void*                ctx,
    const unsigned char* buf,
    size_t               len)
{
    seos_err_t err;
    seos_socket_handle_t* sockHandle = (seos_socket_handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = Seos_socket_write(*sockHandle, buf, &n)) != SEOS_SUCCESS)
    {
        Debug_LOG_WARNING("Error during socket write...error:%d\n", err);
        return -1;
    }

    return n;
}

static int
recvFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    seos_err_t err;
    seos_socket_handle_t* sockHandle = (seos_socket_handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = Seos_socket_read(*sockHandle, buf, &n)) != SEOS_SUCCESS)
    {
        Debug_LOG_WARNING("Error during socket read...error:%d\n", err);
        return -1;
    }

    return n;
}

static int
entropyFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

static seos_err_t
getIndexTls(
    SeosTlsApi_Context* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    bool foundHeader;
    unsigned char buffer[1024];
    const char* request =
        "GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    size_t len;

    Debug_LOG_INFO("Starting TLS handshake..\n");
    if ((err = SeosTlsApi_handshake(ctx)) != SEOS_SUCCESS)
    {
        Debug_LOG_WARNING("SeosTlsApi_handshake failed with err=%i\n", err);
        return err;
    }

    Debug_LOG_INFO("Sending request over TLS..\n");
    len = strlen(request);
    if ((err = SeosTlsApi_write(ctx, request, len)) != SEOS_SUCCESS)
    {
        Debug_LOG_WARNING("SeosTlsApi_write failed with err=%i\n", err);
        return err;
    }

    Debug_LOG_INFO("Reading reply over TLS..\n");
    foundHeader = false;
    for (;;)
    {
        len = sizeof(buffer);
        memset(buffer, 0, sizeof(buffer));
        if ((err = SeosTlsApi_read(ctx, buffer, &len)) != SEOS_SUCCESS)
        {
            Debug_LOG_WARNING("SeosTlsApi_read failed with err=%i\n", err);
            return err;
        }

        if (len > 0
            && strstr("<title>Example Domain</title>", (const char*)buffer) != NULL)
        {
            foundHeader = true;
        }
        else
        {
            break;
        }
    }

    return foundHeader ? SEOS_ERROR_GENERIC : SEOS_SUCCESS;
}

static void
initLib(
    SeosTlsApi_Context*   ctx,
    SeosCryptoApi*        crypto,
    seos_socket_handle_t* sockHandle)
{
    seos_err_t err;
    SeosCryptoApi_Config cryptoCfg =
    {
        .mode = SeosCryptoApi_Mode_LIBRARY,
        .mem = {
            .malloc = malloc,
            .free = free,
        },
        .impl.lib.rng = {
            .entropy = entropyFunc,
            .context = NULL
        }
    };
    seos_nw_client_struct socketCfg =
    {
        .domain = SEOS_AF_INET,
        .type   = SEOS_SOCK_STREAM,
        .name   = TLS_HOST_IP,
        .port   = TLS_HOST_PORT
    };
    SeosTlsApi_Config exampleCfg =
    {
        .mode = SeosTlsApi_Mode_AS_LIBRARY,
        .config.library = {
            .socket = {
                .recv   = recvFunc,
                .send   = sendFunc,
            },
            .flags = SeosTlsLib_Flag_DEBUG,
            .crypto = {
                .policy = NULL,
                .caCert = TLS_HOST_CERT,
                .cipherSuites = {
                    SeosTlsLib_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                },
                .cipherSuitesLen = 1
            },
        }
    };

    err = Seos_client_socket_create(NULL, &socketCfg, sockHandle);
    Debug_ASSERT(SEOS_SUCCESS == err);

    err = SeosCryptoApi_init(crypto, &cryptoCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);

    exampleCfg.config.library.crypto.context = crypto;
    exampleCfg.config.library.socket.context = sockHandle;

    err = SeosTlsApi_init(ctx, &exampleCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);
}

static void
freeLib(
    SeosTlsApi_Context*   ctx,
    SeosCryptoApi*        crypto,
    seos_socket_handle_t* sockHandle)
{
    seos_err_t err;

    err = SeosTlsApi_free(ctx);
    Debug_ASSERT(SEOS_SUCCESS == err);

    err = SeosCryptoApi_free(crypto);
    Debug_ASSERT(SEOS_SUCCESS == err);
}

static void
initRpcClient(
    SeosTlsApi_Context*      ctx,
    SeosTlsRpcServer_Handle* rpcHandle)
{
    seos_err_t err;
    TlsRpcServer_Config hostCfg =
    {
        .ip   = TLS_HOST_IP,
        .port = TLS_HOST_PORT,
    };
    SeosTlsApi_Config clientCfg =
    {
        .mode = SeosTlsApi_Mode_AS_RPC_CLIENT,
    };

    err = TlsRpcServer_init(rpcHandle, hostCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);

    clientCfg.config.client.dataport = tlsClientDataport;
    clientCfg.config.client.handle   = *rpcHandle;

    err = SeosTlsApi_init(ctx, &clientCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);
}

static void
freeRpcClient(
    SeosTlsApi_Context*      ctx,
    SeosTlsRpcServer_Handle* rpcHandle)
{
    seos_err_t err;

    err = TlsRpcServer_free();
    Debug_ASSERT(SEOS_SUCCESS == err);

    err = SeosTlsApi_free(ctx);
    Debug_ASSERT(SEOS_SUCCESS == err);
}

static void
testTls_rpc()
{
    seos_err_t err;
    SeosTlsApi_Context tlsCtx;
    SeosTlsRpcServer_Handle rpcHandle;

    initRpcClient(&tlsCtx, &rpcHandle);

    err = getIndexTls(&tlsCtx);
    Debug_ASSERT(err == SEOS_SUCCESS);

    freeRpcClient(&tlsCtx, &rpcHandle);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testTls_lib()
{
    seos_err_t err;
    SeosTlsApi_Context tlsCtx;
    SeosCryptoApi crypto;
    seos_socket_handle_t socket;

    initLib(&tlsCtx, &crypto, &socket);

    err = getIndexTls(&tlsCtx);
    Debug_ASSERT(err == SEOS_SUCCESS);

    freeLib(&tlsCtx, &crypto, &socket);

    Debug_PRINTF("->%s: OK\n", __func__);
}

int run()
{
    Seos_NwAPP_RT(NULL);

    Debug_PRINTF("Starting tests of SeosTlsApi:\n");

    testTls_lib();
    testTls_rpc();

    Debug_PRINTF("All tests completed.\n");

    return 0;
}

///@}