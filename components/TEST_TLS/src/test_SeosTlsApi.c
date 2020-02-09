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

// In case we need a not-NULL address to test something
#define NOT_NULL ((void*) 1)

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

// Test functions executed once ------------------------------------------------

static void
test_SeosTlsApi_init_ok()
{
    seos_err_t err;
    SeosTlsApi_Context tls;
    static SeosCryptoApi crypto;
    static SeosTlsApi_Config cfgRpcClient =
    {
        .mode = SeosTlsApi_Mode_AS_RPC_CLIENT,
        .config.client.handle = NOT_NULL
    };
    static SeosTlsApi_Config cfgAllSuites =
    {
        .mode = SeosTlsApi_Mode_AS_LIBRARY,
        .config.library = {
            .socket = {
                .recv = recvFunc,
                .send = sendFunc,
            },
            .crypto = {
                .context = &crypto,
                .caCert = TLS_HOST_CERT,
                .cipherSuites = {
                    SeosTlsLib_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    SeosTlsLib_CipherSuite_DHE_RSA_WITH_AES_128_GCM_SHA256
                },
                .cipherSuitesLen = 2
            }
        },
    };
    static SeosTlsApi_Config cfgOneSuite =
    {
        .mode = SeosTlsApi_Mode_AS_LIBRARY,
        .config.library = {
            .socket = {
                .recv = recvFunc,
                .send = sendFunc,
            },
            .crypto = {
                .context = &crypto,
                .caCert = TLS_HOST_CERT,
                .cipherSuites = {
                    SeosTlsLib_CipherSuite_DHE_RSA_WITH_AES_128_GCM_SHA256
                },
                .cipherSuitesLen = 1
            }
        },
    };
    static SeosTlsLib_Policy policy =
    {
        .sessionDigests = {SeosTlsLib_Digest_SHA256},
        .sessionDigestsLen = 1,
        .signatureDigests = {SeosTlsLib_Digest_SHA256},
        .signatureDigestsLen = 1,
        .rsaMinBits = SeosCryptoApi_Key_SIZE_RSA_MIN * 8,
        .dhMinBits = SeosCryptoApi_Key_SIZE_DH_MAX * 8
    };

    err = SeosCryptoApi_init(&crypto, &cryptoCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);

    // Test RPC CLIENT mode
    cfgRpcClient.config.client.dataport = tlsClientDataport,
    err = SeosTlsApi_init(&tls, &cfgRpcClient);
    Debug_ASSERT(SEOS_SUCCESS == err);
    err = SeosTlsApi_free(&tls);
    Debug_ASSERT(SEOS_SUCCESS == err);

    // Test with all ciphersuites enabled
    err = SeosTlsApi_init(&tls, &cfgAllSuites);
    Debug_ASSERT(SEOS_SUCCESS == err);
    err = SeosTlsApi_free(&tls);
    Debug_ASSERT(SEOS_SUCCESS == err);

    // Test with only one ciphersuite enabled
    err = SeosTlsApi_init(&tls, &cfgOneSuite);
    Debug_ASSERT(SEOS_SUCCESS == err);
    err = SeosTlsApi_free(&tls);
    Debug_ASSERT(SEOS_SUCCESS == err);

    // Test with all ciphersuites and policy options
    cfgAllSuites.config.library.crypto.policy = &policy;
    err = SeosTlsApi_init(&tls, &cfgAllSuites);
    Debug_ASSERT(SEOS_SUCCESS == err);
    err = SeosTlsApi_free(&tls);
    Debug_ASSERT(SEOS_SUCCESS == err);

    err = SeosCryptoApi_free(&crypto);
    Debug_ASSERT(SEOS_SUCCESS == err);

    TEST_OK();
}

static void
test_SeosTlsApi_init_fail()
{
    seos_err_t err;
    SeosTlsApi_Context tls;
    static SeosCryptoApi crypto;
    static SeosTlsLib_Policy badPolicy, goodPolicy =
    {
        .sessionDigests = {SeosTlsLib_Digest_SHA256},
        .sessionDigestsLen = 1,
        .signatureDigests = {SeosTlsLib_Digest_SHA256},
        .signatureDigestsLen = 1,
        .rsaMinBits = SeosCryptoApi_Key_SIZE_RSA_MIN * 8,
        .dhMinBits = SeosCryptoApi_Key_SIZE_DH_MIN * 8
    };
    static SeosTlsApi_Config badCfg, goodCfg =
    {
        .mode = SeosTlsApi_Mode_AS_LIBRARY,
        .config.library = {
            .socket = {
                .recv = recvFunc,
                .send = sendFunc,
            },
            .crypto = {
                .context = &crypto,
                .policy = NULL,
                .caCert = TLS_HOST_CERT,
                .cipherSuites = {
                    SeosTlsLib_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    SeosTlsLib_CipherSuite_DHE_RSA_WITH_AES_128_GCM_SHA256
                },
                .cipherSuitesLen = 2
            }
        },
    };
    static SeosTlsApi_Config cfgRpcClient =
    {
        .mode = SeosTlsApi_Mode_AS_RPC_CLIENT,
        .config.client.handle = NOT_NULL
    };

    cfgRpcClient.config.client.dataport = tlsClientDataport,

    // Test in RPC Client mode without dataport
    memcpy(&badCfg, &cfgRpcClient, sizeof(SeosTlsApi_Config));
    badCfg.config.client.dataport = NULL;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_INVALID_PARAMETER == err);

    // Test in RPC Client mode without client handle
    memcpy(&badCfg, &cfgRpcClient, sizeof(SeosTlsApi_Config));
    badCfg.config.client.handle = NULL;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_INVALID_PARAMETER == err);

    err = SeosCryptoApi_init(&crypto, &cryptoCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);

    // Provide bad mode
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.mode = 666;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_NOT_SUPPORTED == err);

    // No RECV callback
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.socket.recv = NULL;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_INVALID_PARAMETER == err);

    // No SEND callback
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.socket.send = NULL;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_INVALID_PARAMETER == err);

    // No crypto context
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.context = NULL;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_INVALID_PARAMETER == err);

    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.policy = &badPolicy;

    // Invalid session digest algorithm
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.sessionDigests[1] = 666;
    badPolicy.sessionDigestsLen = 2;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_NOT_SUPPORTED == err);

    // Too many session digests
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.sessionDigestsLen = SeosTlsLib_MAX_DIGESTS + 1;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_INVALID_PARAMETER == err);

    // Invalid signature digest algorithm
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.signatureDigests[1] = 666;
    badPolicy.signatureDigestsLen = 2;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_NOT_SUPPORTED == err);

    // Too many signature digests
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.signatureDigestsLen = SeosTlsLib_MAX_DIGESTS + 1;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_INVALID_PARAMETER == err);

    // Min size for DH too big
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.dhMinBits = (SeosCryptoApi_Key_SIZE_DH_MAX * 8) + 1;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_NOT_SUPPORTED == err);

    // Min size for DH too small
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.dhMinBits = (SeosCryptoApi_Key_SIZE_DH_MIN * 8) - 1;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_NOT_SUPPORTED == err);

    // Min size for RSA too big
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.rsaMinBits = (SeosCryptoApi_Key_SIZE_RSA_MAX * 8) + 1;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_NOT_SUPPORTED == err);

    // Min size for RSA too small
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.rsaMinBits = (SeosCryptoApi_Key_SIZE_RSA_MIN * 8) - 1;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_NOT_SUPPORTED == err);

    // Cert is not properly PEM encoded
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    // Invalidate the "-----BEGIN" part of the PEM encoded cert
    memset(badCfg.config.library.crypto.caCert, 0, 10);
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_INVALID_PARAMETER == err);

    // Invalid cipher suite
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.cipherSuites[0] = 666;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_NOT_SUPPORTED == err);

    // Too many cipher suites
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.cipherSuitesLen = SeosTlsLib_MAX_CIPHERSUITES + 1;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_INVALID_PARAMETER == err);

    // No ciphersuites at all
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.cipherSuitesLen = 0;
    err = SeosTlsApi_init(&tls, &badCfg);
    Debug_ASSERT(SEOS_ERROR_INVALID_PARAMETER == err);

    err = SeosCryptoApi_free(&crypto);
    Debug_ASSERT(SEOS_SUCCESS == err);

    TEST_OK();
}

static void
test_SeosTlsApi_free_ok()
{
    seos_err_t err;
    SeosTlsApi_Context tls;
    static SeosCryptoApi crypto;
    static SeosTlsApi_Config cfg =
    {
        .mode = SeosTlsApi_Mode_AS_LIBRARY,
        .config.library = {
            .socket = {
                .recv = recvFunc,
                .send = sendFunc,
            },
            .crypto = {
                .context = &crypto,
                .caCert = TLS_HOST_CERT,
                .cipherSuites = {
                    SeosTlsLib_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                },
                .cipherSuitesLen = 1
            }
        },
    };

    err = SeosCryptoApi_init(&crypto, &cryptoCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);

    err = SeosTlsApi_init(&tls, &cfg);
    Debug_ASSERT(SEOS_SUCCESS == err);
    err = SeosTlsApi_free(&tls);
    Debug_ASSERT(SEOS_SUCCESS == err);

    err = SeosCryptoApi_free(&crypto);
    Debug_ASSERT(SEOS_SUCCESS == err);

    TEST_OK();
}

static void
test_SeosTlsApi_free_fail()
{
    seos_err_t err;

    // Empty context
    err = SeosTlsApi_free(NULL);
    Debug_ASSERT(SEOS_ERROR_INVALID_PARAMETER == err);

    TEST_OK();
}

// Test functions executed for different API modes -----------------------------

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

    Debug_PRINTF("Testing TLS API:\n");

    // Test init and free independent of API mode
    test_SeosTlsApi_init_ok();
    test_SeosTlsApi_init_fail();

    test_SeosTlsApi_free_ok();
    test_SeosTlsApi_free_fail();

    Debug_PRINTF("\n");

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