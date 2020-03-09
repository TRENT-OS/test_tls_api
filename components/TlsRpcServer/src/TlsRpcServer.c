/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "TestConfig.h"

#include "SeosCryptoApi.h"
#include "SeosTlsApi.h"

#include "LibDebug/Debug.h"
#include "seos_nw_api.h"

#include "TlsRpcServer.h"

#include <camkes.h>
#include <string.h>

#define MAX_NW_SIZE 2048

extern seos_err_t Seos_NwAPP_RT(
    Seos_nw_context ctx);

static int
sendFunc(
    void*                ctx,
    const unsigned char* buf,
    size_t               len);

static int
recvFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len);

static int
entropy(
    void*          ctx,
    unsigned char* buf,
    size_t         len);

static SeosTlsApi_Config tlsCfg =
{
    .mode = SeosTlsApi_Mode_RPC_SERVER,
    .config.server.library = {
        .socket = {
            .recv   = recvFunc,
            .send   = sendFunc,
        },
        .flags = SeosTlsLib_Flag_DEBUG,
        .crypto = {
            .policy = NULL,
            // This is the "DigiCert SHA2 Secure Server CA" cert for verifying
            // the cert given by www.example.com!
            .caCert = TLS_HOST_CERT,
            .cipherSuites = {
                SeosTlsLib_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            },
            .cipherSuitesLen = 1
        }
    }
};
static SeosCryptoApi_Config cryptoCfg =
{
    .mode = SeosCryptoApi_Mode_LIBRARY,
    .mem = {
        .malloc = malloc,
        .free = free,
    },
    .impl.lib.rng.entropy = entropy
};
static seos_nw_client_struct socketCfg =
{
    .domain = SEOS_AF_INET,
    .type   = SEOS_SOCK_STREAM,
    .name   = TLS_HOST_IP,
    .port   = TLS_HOST_PORT
};

static SeosTlsApiH hTls;
static SeosCryptoApi cryptoContext;
static seos_socket_handle_t socket;

// Private static functions ----------------------------------------------------

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
        Debug_LOG_ERROR("Error during socket write...error:%d", err);
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
        Debug_LOG_ERROR("Error during socket read...error:%d", err);
        return -1;
    }

    return n;
}

static int
entropy(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

// Public functions ------------------------------------------------------------

// We need to give the TLS RPC Server the context to use for a specific client;
// we have only one client here, so it is easy.
SeosTlsApiH
SeosTlsRpc_Server_getSeosTlsApi(
    void)
{
    return hTls;
}

seos_err_t
TlsRpcServer_init(
    void)
{
    seos_err_t err;

    // Apparently this needs to be done in the RPC thread...?!
    Seos_NwAPP_RT(NULL);

    err = SeosCryptoApi_init(&cryptoContext, &cryptoCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);

    tlsCfg.config.server.dataport               = tlsServerDataport;
    tlsCfg.config.server.library.crypto.context = &cryptoContext;
    // Socket will be connected later, by call to _connectSocket()
    tlsCfg.config.server.library.socket.context = &socket;

    err = SeosTlsApi_init(&hTls, &tlsCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);

    return 0;
}

seos_err_t
TlsRpcServer_connectSocket(
    void)
{
    return Seos_client_socket_create(NULL, &socketCfg, &socket);
}

seos_err_t
TlsRpcServer_closeSocket(
    void)
{
    return Seos_socket_close(socket);
}

seos_err_t
TlsRpcServer_free(
    void)
{
    seos_err_t err;

    err = SeosTlsApi_free(hTls);
    Debug_ASSERT(SEOS_SUCCESS == err);

    err = SeosCryptoApi_free(&cryptoContext);
    Debug_ASSERT(SEOS_SUCCESS == err);

    return 0;
}
