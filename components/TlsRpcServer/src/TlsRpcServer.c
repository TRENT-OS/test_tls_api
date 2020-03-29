/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "TestConfig.h"

#include "SeosCryptoApi.h"
#include "SeosTlsApi.h"

#include "LibDebug/Debug.h"
#include "OS_Network.h"

#include "TlsRpcServer.h"

#include <camkes.h>
#include <string.h>

#define MAX_NW_SIZE 2048

extern seos_err_t OS_NetworkAPP_RT(
    OS_Network_context_t ctx);

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
static OS_NetworkClient_socket_t socketCfg =
{
    .domain = OS_AF_INET,
    .type   = OS_SOCK_STREAM,
    .name   = TLS_HOST_IP,
    .port   = TLS_HOST_PORT
};

static SeosTlsApiH hTls;
static SeosCryptoApiH hCrypto;
static OS_NetworkSocket_handle_t socket;

// Private static functions ----------------------------------------------------

static int
sendFunc(
    void*                ctx,
    const unsigned char* buf,
    size_t               len)
{
    seos_err_t err;
    OS_NetworkSocket_handle_t* sockHandle = (OS_NetworkSocket_handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = OS_NetworkSocket_write(*sockHandle, buf, &n)) != SEOS_SUCCESS)
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
    OS_NetworkSocket_handle_t* sockHandle = (OS_NetworkSocket_handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = OS_NetworkSocket_read(*sockHandle, buf, &n)) != SEOS_SUCCESS)
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
    OS_NetworkAPP_RT(NULL);

    err = SeosCryptoApi_init(&hCrypto, &cryptoCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);

    tlsCfg.config.server.dataport               = tlsServerDataport;
    tlsCfg.config.server.library.crypto.handle  = hCrypto;
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
    return OS_NetworkClientSocket_create(NULL, &socketCfg, &socket);
}

seos_err_t
TlsRpcServer_closeSocket(
    void)
{
    return OS_NetworkSocket_close(socket);
}

seos_err_t
TlsRpcServer_free(
    void)
{
    seos_err_t err;

    err = SeosTlsApi_free(hTls);
    Debug_ASSERT(SEOS_SUCCESS == err);

    err = SeosCryptoApi_free(hCrypto);
    Debug_ASSERT(SEOS_SUCCESS == err);

    return 0;
}
