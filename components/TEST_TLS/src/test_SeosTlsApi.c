/**
 * @addtogroup TlsApi_Tests
 * @{
 *
 * @file test_SeosTlsApi.c
 *
 * @brief Unit tests for the SEOS TLS API
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "TestConfig.h"
#include "TestMacros.h"

#include "SeosCryptoApi.h"
#include "SeosTlsApi.h"
#include "TlsRpcServer.h"

#include "seos_nw_api.h"

#ifdef WAIT_FOR_CLIENT_CONNECT
#include <sel4/sel4.h> // needed for seL4_yield()
#endif

#include <camkes.h>
#include <string.h>

#define MAX_NW_SIZE 2048

extern seos_err_t
Seos_NwAPP_RT(
    Seos_nw_context ctx);

static int
entropyFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len);

static SeosCryptoApi_Config cryptoCfg =
{
    .mode = SeosCryptoApi_Mode_LIBRARY,
    .mem.malloc = malloc,
    .mem.free = free,
    .impl.lib.rng.entropy = entropyFunc,
};

// Private functions -----------------------------------------------------------

static int
sendFunc(
    void*                ctx,
    const unsigned char* buf,
    size_t               len)
{
    seos_err_t err;
    seos_socket_handle_t* socket = (seos_socket_handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = Seos_socket_write(*socket, buf, &n)) != SEOS_SUCCESS)
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
    seos_socket_handle_t* socket = (seos_socket_handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = Seos_socket_read(*socket, buf, &n)) != SEOS_SUCCESS)
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
connectSocket(
    seos_socket_handle_t* socket)
{
    seos_err_t err;
    seos_nw_client_struct socketCfg =
    {
        .domain = SEOS_AF_INET,
        .type   = SEOS_SOCK_STREAM,
        .name   = TLS_HOST_IP,
        .port   = TLS_HOST_PORT
    };

    err = Seos_client_socket_create(NULL, &socketCfg, socket);

#ifdef WAIT_FOR_CLIENT_CONNECT
    Debug_PRINTFLN("%s: Waiting for a while before trying to use socket..", __func__);
    for (size_t i = 0; i < 500; i++)
    {
        seL4_Yield();
    }
#endif

    return err;
}

static seos_err_t
closeSocket(
    seos_socket_handle_t* socket)
{
    return Seos_socket_close(*socket);
}

static void
test_SeosTlsApi_mode(
    SeosTlsApi_Context* api,
    seos_socket_handle_t* socket)
{
    char mode[128];

    switch (api->mode)
    {
    case SeosTlsApi_Mode_AS_LIBRARY:
        strcpy(mode, "SeosTlsApi_Mode_AS_LIBRARY");
        break;
    case SeosTlsApi_Mode_AS_RPC_CLIENT:
        strcpy(mode, "SeosTlsApi_Mode_AS_RPC_CLIENT");
        break;
    default:
        Debug_ASSERT(1 == 0);
    }

    Debug_PRINTF("Testing TLS API in %s mode:\n", mode);
}

// Public functions ------------------------------------------------------------

int run()
{
    seos_err_t err;
    SeosTlsApi_Context tls;
    static SeosCryptoApi crypto;
    static seos_socket_handle_t socket;
    static SeosTlsApi_Config localCfg =
    {
        .mode = SeosTlsApi_Mode_AS_LIBRARY,
        .config.library = {
            .socket = {
                .context = &socket,
                .recv = recvFunc,
                .send = sendFunc,
            },
            .flags = SeosTlsLib_Flag_DEBUG,
            .crypto = {
                .context = &crypto,
                .caCert = TLS_HOST_CERT,
                .cipherSuites = {
                    SeosTlsLib_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                },
                .cipherSuitesLen = 1
            },
        }
    };
    SeosTlsApi_Config remoteCfg =
    {
        .mode = SeosTlsApi_Mode_AS_RPC_CLIENT,
        .config.client.dataport = tlsClientDataport,
    };

    Seos_NwAPP_RT(NULL);

    // Test library mode
    err = connectSocket(&socket);
    Debug_ASSERT(SEOS_SUCCESS == err);
    err = SeosCryptoApi_init(&crypto, &cryptoCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);
    err = SeosTlsApi_init(&tls, &localCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);
    test_SeosTlsApi_mode(&tls, &socket);
    err = SeosTlsApi_free(&tls);
    Debug_ASSERT(SEOS_SUCCESS == err);
    err = SeosCryptoApi_free(&crypto);
    Debug_ASSERT(SEOS_SUCCESS == err);
    err = closeSocket(&socket);
    Debug_ASSERT(SEOS_SUCCESS == err);

    Debug_PRINTF("\n");

    err = TlsRpcServer_init(&remoteCfg.config.client.handle);
    Debug_ASSERT(SEOS_SUCCESS == err);

    // Test RPC client mode (and implicitly the RPC server side as well)
    err = TlsRpcServer_connectSocket();
    Debug_ASSERT(SEOS_SUCCESS == err);
    err = SeosTlsApi_init(&tls, &remoteCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);
    test_SeosTlsApi_mode(&tls, NULL);
    err = SeosTlsApi_free(&tls);
    Debug_ASSERT(SEOS_SUCCESS == err);
    err = TlsRpcServer_closeSocket();
    Debug_ASSERT(SEOS_SUCCESS == err);
    err = TlsRpcServer_free();
    Debug_ASSERT(SEOS_SUCCESS == err);

    Debug_PRINTF("All tests successfully completed.\n");

    return 0;
}

///@}