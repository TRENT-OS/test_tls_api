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

#define MAX_NW_SIZE 256

// Use for read/write testing with ECHO server
#define ECHO_STRING "ThisIsATestStringPleaseSendItBackToMe!!"

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
    seos_socket_handle_t* socket = (seos_socket_handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = Seos_socket_read(*socket, buf, &n)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("Error during socket read...error:%d", err);
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
    Debug_LOG_INFO("%s: Waiting for a while before trying to use socket..",
                   __func__);
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

static seos_err_t
resetSocket(
    seos_socket_handle_t* socket)
{
    seos_err_t err;

    // Reset either the local socket or the one on the RPC server
    if (NULL != socket)
    {
        if ((err = closeSocket(socket)) != SEOS_SUCCESS)
        {
            return err;
        }
        if ((err = connectSocket(socket)) != SEOS_SUCCESS)
        {
            return err;
        }
    }
    else
    {
        if ((err = TlsRpcServer_closeSocket()) != SEOS_SUCCESS)
        {
            return err;
        }
        if ((err = TlsRpcServer_connectSocket()) != SEOS_SUCCESS)
        {
            return err;
        }
    }

    return SEOS_SUCCESS;
}

// Test functions executed once ------------------------------------------------

static void
test_SeosTlsApi_init_pos()
{
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

    TEST_START();

    TEST_SUCCESS(SeosCryptoApi_init(&crypto, &cryptoCfg));

    // Test RPC CLIENT mode
    cfgRpcClient.config.client.dataport = tlsClientDataport;
    TEST_SUCCESS(SeosTlsApi_init(&tls, &cfgRpcClient));
    TEST_SUCCESS(SeosTlsApi_free(&tls));

    // Test with all ciphersuites enabled
    TEST_SUCCESS(SeosTlsApi_init(&tls, &cfgAllSuites));
    TEST_SUCCESS(SeosTlsApi_free(&tls));

    // Test with only one ciphersuite enabled
    TEST_SUCCESS(SeosTlsApi_init(&tls, &cfgOneSuite));
    TEST_SUCCESS(SeosTlsApi_free(&tls));

    // Test with all ciphersuites and policy options
    cfgAllSuites.config.library.crypto.policy = &policy;
    TEST_SUCCESS(SeosTlsApi_init(&tls, &cfgAllSuites));
    TEST_SUCCESS(SeosTlsApi_free(&tls));

    TEST_SUCCESS(SeosCryptoApi_free(&crypto));

    TEST_FINISH();
}

static void
test_SeosTlsApi_init_neg()
{
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

    TEST_START();

    cfgRpcClient.config.client.dataport = tlsClientDataport,

    // Test in RPC Client mode without dataport
    memcpy(&badCfg, &cfgRpcClient, sizeof(SeosTlsApi_Config));
    badCfg.config.client.dataport = NULL;
    TEST_INVAL_PARAM(SeosTlsApi_init(&tls, &badCfg));

    // Test in RPC Client mode without client handle
    memcpy(&badCfg, &cfgRpcClient, sizeof(SeosTlsApi_Config));
    badCfg.config.client.handle = NULL;
    TEST_INVAL_PARAM(SeosTlsApi_init(&tls, &badCfg));

    TEST_SUCCESS(SeosCryptoApi_init(&crypto, &cryptoCfg));

    // Provide bad mode
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.mode = 666;
    TEST_NOT_SUPP(SeosTlsApi_init(&tls, &badCfg));

    // No RECV callback
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.socket.recv = NULL;
    TEST_INVAL_PARAM(SeosTlsApi_init(&tls, &badCfg));

    // No SEND callback
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.socket.send = NULL;
    TEST_INVAL_PARAM(SeosTlsApi_init(&tls, &badCfg));

    // No crypto context
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.context = NULL;
    TEST_INVAL_PARAM(SeosTlsApi_init(&tls, &badCfg));

    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.policy = &badPolicy;

    // Invalid session digest algorithm
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.sessionDigests[1] = 666;
    badPolicy.sessionDigestsLen = 2;
    TEST_NOT_SUPP(SeosTlsApi_init(&tls, &badCfg));

    // Too many session digests
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.sessionDigestsLen = SeosTlsLib_MAX_DIGESTS + 1;
    TEST_INVAL_PARAM(SeosTlsApi_init(&tls, &badCfg));

    // Invalid signature digest algorithm
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.signatureDigests[1] = 666;
    badPolicy.signatureDigestsLen = 2;
    TEST_NOT_SUPP(SeosTlsApi_init(&tls, &badCfg));

    // Too many signature digests
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.signatureDigestsLen = SeosTlsLib_MAX_DIGESTS + 1;
    TEST_INVAL_PARAM(SeosTlsApi_init(&tls, &badCfg));

    // Min size for DH too big
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.dhMinBits = (SeosCryptoApi_Key_SIZE_DH_MAX * 8) + 1;
    TEST_NOT_SUPP(SeosTlsApi_init(&tls, &badCfg));

    // Min size for DH too small
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.dhMinBits = (SeosCryptoApi_Key_SIZE_DH_MIN * 8) - 1;
    TEST_NOT_SUPP(SeosTlsApi_init(&tls, &badCfg));

    // Min size for RSA too big
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.rsaMinBits = (SeosCryptoApi_Key_SIZE_RSA_MAX * 8) + 1;
    TEST_NOT_SUPP(SeosTlsApi_init(&tls, &badCfg));

    // Min size for RSA too small
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.rsaMinBits = (SeosCryptoApi_Key_SIZE_RSA_MIN * 8) - 1;
    TEST_NOT_SUPP(SeosTlsApi_init(&tls, &badCfg));

    // Cert is not properly PEM encoded
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    // Invalidate the "-----BEGIN" part of the PEM encoded cert
    memset(badCfg.config.library.crypto.caCert, 0, 10);
    TEST_INVAL_PARAM(SeosTlsApi_init(&tls, &badCfg));

    // Invalid cipher suite
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.cipherSuites[0] = 666;
    TEST_NOT_SUPP(SeosTlsApi_init(&tls, &badCfg));

    // Too many cipher suites
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.cipherSuitesLen = SeosTlsLib_MAX_CIPHERSUITES + 1;
    TEST_INVAL_PARAM(SeosTlsApi_init(&tls, &badCfg));

    // No ciphersuites at all
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.cipherSuitesLen = 0;
    TEST_INVAL_PARAM(SeosTlsApi_init(&tls, &badCfg));

    TEST_SUCCESS(SeosCryptoApi_free(&crypto));

    TEST_FINISH();
}

static void
test_SeosTlsApi_free_pos()
{

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

    TEST_START();

    TEST_SUCCESS(SeosCryptoApi_init(&crypto, &cryptoCfg));

    // Simply init it and free again
    TEST_SUCCESS(SeosTlsApi_init(&tls, &cfg));
    TEST_SUCCESS(SeosTlsApi_free(&tls));

    TEST_SUCCESS(SeosCryptoApi_free(&crypto));

    TEST_FINISH();
}

static void
test_SeosTlsApi_free_neg()
{
    TEST_START();

    // Empty context
    TEST_INVAL_PARAM(SeosTlsApi_free(NULL));

    TEST_FINISH();
}

// Test functions executed for different API modes -----------------------------

static void
test_SeosTlsApi_handshake_pos(
    SeosTlsApi_Context* api)
{
    TEST_START(api->mode);

    // Do the handshake
    TEST_SUCCESS(SeosTlsApi_handshake(api));

    TEST_FINISH();
}

static void
test_SeosTlsApi_handshake_neg(
    SeosTlsApi_Context* api)
{
    TEST_START(api->mode);

    // Handshake again on an already existing TLS session
    TEST_OP_DENIED(SeosTlsApi_handshake(api));

    // Without context
    TEST_INVAL_PARAM(SeosTlsApi_handshake(NULL));

    TEST_FINISH();
}

static void
test_SeosTlsApi_write_neg(
    SeosTlsApi_Context* api)
{
    char* request = ECHO_STRING;
    size_t len = sizeof(request);

    TEST_START(api->mode);

    // No context
    TEST_INVAL_PARAM(SeosTlsApi_write(NULL, request, len));

    // No buffer
    TEST_INVAL_PARAM(SeosTlsApi_write(api, NULL, len));

    // Zero length write
    len = 0;
    TEST_INVAL_PARAM(SeosTlsApi_write(api, request, len));

    TEST_FINISH();
}

static void
test_SeosTlsApi_write_pos(
    SeosTlsApi_Context* api)
{
    char request[] = ECHO_STRING;
    size_t len = sizeof(request);

    TEST_START(api->mode);

    /*
     * Before executing this test, a TLS sessions needs to be established
     */

    TEST_SUCCESS(SeosTlsApi_write(api, request, len));

    TEST_FINISH();
}

static void
test_SeosTlsApi_read_neg(
    SeosTlsApi_Context* api)
{
    unsigned char buffer[1024];
    size_t len = sizeof(buffer);

    TEST_START(api->mode);

    // No context
    TEST_INVAL_PARAM(SeosTlsApi_read(NULL, buffer, &len));

    // No buffer
    TEST_INVAL_PARAM(SeosTlsApi_read(api, NULL, &len));

    // No len
    TEST_INVAL_PARAM(SeosTlsApi_read(api, buffer, NULL));

    // Zero length
    len = 0;
    TEST_INVAL_PARAM(SeosTlsApi_read(api, buffer, &len));

    TEST_FINISH();
}

static void
test_SeosTlsApi_read_pos(
    SeosTlsApi_Context* api)
{
    unsigned char buffer[1024];
    const char answer[] = ECHO_STRING;
    size_t len = sizeof(buffer);

    TEST_START(api->mode);

    /*
     * Before executing this test, we should have sent the ECHO_STRING to the
     * echo server already as part of the write test.
     */

    len = sizeof(buffer);
    memset(buffer, 0, sizeof(buffer));
    TEST_SUCCESS(SeosTlsApi_read(api, buffer, &len));
    TEST_TRUE(len == sizeof(answer));
    TEST_TRUE(!memcmp(buffer, answer, len));

    TEST_FINISH();
}

static void
test_SeosTlsApi_reset_pos(
    SeosTlsApi_Context*   api,
    seos_socket_handle_t* socket)
{
    TEST_START(api->mode);

    /*
     * For this test we expect the socket to be closed and the TLS session to
     * be finished as well.
     */

    // Reset the API and the socket
    TEST_SUCCESS(SeosTlsApi_reset(api));
    TEST_SUCCESS(resetSocket(socket));
    // Do the handshake again
    TEST_SUCCESS(SeosTlsApi_handshake(api));

    TEST_FINISH();
}

static void
test_SeosTlsApi_reset_neg(
    SeosTlsApi_Context*   api,
    seos_socket_handle_t* socket)
{
    TEST_START(api->mode);

    TEST_INVAL_PARAM(SeosTlsApi_reset(NULL));

    TEST_FINISH();
}

static void
test_SeosTlsApi_mode(
    SeosTlsApi_Context*   api,
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
        TEST_TRUE(1 == 0);
    }

    Debug_LOG_INFO("Testing TLS API in %s mode:", mode);

    /*
     * The following three (six) tests should follow in this order:
     * 1. handshake_pos() establishes a TLS session
     * 2. handshake_neg() requires an established session, but does not
     *    change it.
     * 3. write_neg() does not change the TLS session
     * 4. write_pos() writes to the echo server, does not read anything and does
     *    not change the session.
     * 5. read_neg() does not change the TLS session.
     * 6. read_pos() reads from the echo server (the string that write_pos() has
     *    written there.
     *
     * The echo server then will close the socket!
     *
     * TODO: Ideally, all these tests would be self-contained and not require any
     *       particular order, but as long as the NW is so slow, it makes sense
     *       to re-use established sockets and sessions.
     */

    test_SeosTlsApi_handshake_pos(api);
    test_SeosTlsApi_handshake_neg(api);

    test_SeosTlsApi_write_neg(api);
    test_SeosTlsApi_write_pos(api);

    test_SeosTlsApi_read_neg(api);
    test_SeosTlsApi_read_pos(api);

    /*
     * Here the TLS session and socket should be closed by the server. We will
     * now re-set it with these tests to see if we can make the handshake work
     * again.
     */

    test_SeosTlsApi_reset_neg(api, socket);
    test_SeosTlsApi_reset_pos(api, socket);
}

// Public functions ------------------------------------------------------------

int run()
{
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

    Debug_LOG_INFO("Testing TLS API:");

    // Test init and free independent of API mode
    test_SeosTlsApi_init_pos();
    test_SeosTlsApi_init_neg();

    test_SeosTlsApi_free_pos();
    test_SeosTlsApi_free_neg();

    Debug_LOG_INFO("");

    Seos_NwAPP_RT(NULL);

    // Test library mode
    TEST_SUCCESS(connectSocket(&socket));
    TEST_SUCCESS(SeosCryptoApi_init(&crypto, &cryptoCfg));
    TEST_SUCCESS(SeosTlsApi_init(&tls, &localCfg));
    test_SeosTlsApi_mode(&tls, &socket);
    TEST_SUCCESS(SeosTlsApi_free(&tls));
    TEST_SUCCESS(SeosCryptoApi_free(&crypto));
    TEST_SUCCESS(closeSocket(&socket));

    Debug_LOG_INFO("");

    TEST_SUCCESS(TlsRpcServer_init(&remoteCfg.config.client.handle));

    // Test RPC client mode (and implicitly the RPC server side as well)
    TEST_SUCCESS(TlsRpcServer_connectSocket());
    TEST_SUCCESS(SeosTlsApi_init(&tls, &remoteCfg));
    test_SeosTlsApi_mode(&tls, NULL);
    TEST_SUCCESS(SeosTlsApi_free(&tls));
    TEST_SUCCESS(TlsRpcServer_closeSocket());
    TEST_SUCCESS(TlsRpcServer_free());

    Debug_LOG_INFO("All tests successfully completed.");

    return 0;
}

///@}
