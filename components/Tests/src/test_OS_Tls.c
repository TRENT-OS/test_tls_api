/**
 * @addtogroup TlsApi_Tests
 * @{
 *
 * @file test_OS_Tls.c
 *
 * @brief Unit tests for the OS TLS API
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "TestConfig.h"
#include "TestMacros.h"

#include "SeosCryptoApi.h"
#include "SeosTlsApi.h"
#include "TlsRpcServer.h"

#include "OS_Network.h"

#include <camkes.h>
#include <string.h>

#define MAX_NW_SIZE 256

// Use for read/write testing with ECHO server
#define ECHO_STRING "ThisIsATestStringPleaseSendItBackToMe!!"

// In case we need a not-NULL address to test something
#define NOT_NULL ((void*) 1)

extern seos_err_t
OS_NetworkAPP_RT(
    OS_Network_Context_t ctx);

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
    OS_NetworkSocket_Handle_t* socket = (OS_NetworkSocket_Handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = OS_NetworkSocket_write(*socket, buf, &n)) != SEOS_SUCCESS)
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
    OS_NetworkSocket_Handle_t* socket = (OS_NetworkSocket_Handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = OS_NetworkSocket_read(*socket, buf, &n)) != SEOS_SUCCESS)
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
    OS_NetworkSocket_Handle_t* socket)
{
    OS_Network_Socket_t socketCfg =
    {
        .domain = OS_AF_INET,
        .type   = OS_SOCK_STREAM,
        .name   = TLS_HOST_IP,
        .port   = TLS_HOST_PORT
    };

    return OS_NetworkSocket_create(NULL, &socketCfg, socket);
}

static seos_err_t
closeSocket(
    OS_NetworkSocket_Handle_t* socket)
{
    return OS_NetworkSocket_close(*socket);
}

static seos_err_t
resetSocket(
    OS_NetworkSocket_Handle_t* socket)
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
test_OS_Tls_init_pos()
{
    SeosTlsApiH hTls;
    SeosCryptoApiH hCrypto;
    static SeosTlsApi_Config cfgRpcClient =
    {
        .mode = SeosTlsApi_Mode_RPC_CLIENT,
    };
    static SeosTlsApi_Config cfgAllSuites =
    {
        .mode = SeosTlsApi_Mode_LIBRARY,
        .config.library = {
            .socket = {
                .recv = recvFunc,
                .send = sendFunc,
            },
            .crypto = {
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
        .mode = SeosTlsApi_Mode_LIBRARY,
        .config.library = {
            .socket = {
                .recv = recvFunc,
                .send = sendFunc,
            },
            .crypto = {
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

    TEST_SUCCESS(SeosCryptoApi_init(&hCrypto, &cryptoCfg));
    cfgAllSuites.config.library.crypto.handle = hCrypto;
    cfgOneSuite.config.library.crypto.handle = hCrypto;

    // Test RPC CLIENT mode
    cfgRpcClient.config.client.dataport = tlsClientDataport;
    TEST_SUCCESS(SeosTlsApi_init(&hTls, &cfgRpcClient));
    TEST_SUCCESS(SeosTlsApi_free(hTls));

    // Test with all ciphersuites enabled
    TEST_SUCCESS(SeosTlsApi_init(&hTls, &cfgAllSuites));
    TEST_SUCCESS(SeosTlsApi_free(hTls));

    // Test with only one ciphersuite enabled
    TEST_SUCCESS(SeosTlsApi_init(&hTls, &cfgOneSuite));
    TEST_SUCCESS(SeosTlsApi_free(hTls));

    // Test with all ciphersuites and policy options
    cfgAllSuites.config.library.crypto.policy = &policy;
    TEST_SUCCESS(SeosTlsApi_init(&hTls, &cfgAllSuites));
    TEST_SUCCESS(SeosTlsApi_free(hTls));

    TEST_SUCCESS(SeosCryptoApi_free(hCrypto));

    TEST_FINISH();
}

static void
test_OS_Tls_init_neg()
{
    SeosTlsApiH hTls;
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
        .mode = SeosTlsApi_Mode_LIBRARY,
        .config.library = {
            .socket = {
                .recv = recvFunc,
                .send = sendFunc,
            },
            .crypto = {
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
        .mode = SeosTlsApi_Mode_RPC_CLIENT,
    };

    TEST_START();

    cfgRpcClient.config.client.dataport = tlsClientDataport;
    TEST_SUCCESS(SeosCryptoApi_init(&goodCfg.config.library.crypto.handle,
                                    &cryptoCfg));

    // Test in RPC Client mode without dataport
    memcpy(&badCfg, &cfgRpcClient, sizeof(SeosTlsApi_Config));
    badCfg.config.client.dataport = NULL;
    TEST_INVAL_PARAM(SeosTlsApi_init(&hTls, &badCfg));

    // Provide bad mode
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.mode = 666;
    TEST_NOT_SUPP(SeosTlsApi_init(&hTls, &badCfg));

    // No RECV callback
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.socket.recv = NULL;
    TEST_INVAL_PARAM(SeosTlsApi_init(&hTls, &badCfg));

    // No SEND callback
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.socket.send = NULL;
    TEST_INVAL_PARAM(SeosTlsApi_init(&hTls, &badCfg));

    // No crypto context
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.handle = NULL;
    TEST_INVAL_PARAM(SeosTlsApi_init(&hTls, &badCfg));

    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.policy = &badPolicy;

    // Invalid session digest algorithm
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.sessionDigests[1] = 666;
    badPolicy.sessionDigestsLen = 2;
    TEST_NOT_SUPP(SeosTlsApi_init(&hTls, &badCfg));

    // Too many session digests
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.sessionDigestsLen = SeosTlsLib_MAX_DIGESTS + 1;
    TEST_INVAL_PARAM(SeosTlsApi_init(&hTls, &badCfg));

    // Invalid signature digest algorithm
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.signatureDigests[1] = 666;
    badPolicy.signatureDigestsLen = 2;
    TEST_NOT_SUPP(SeosTlsApi_init(&hTls, &badCfg));

    // Too many signature digests
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.signatureDigestsLen = SeosTlsLib_MAX_DIGESTS + 1;
    TEST_INVAL_PARAM(SeosTlsApi_init(&hTls, &badCfg));

    // Min size for DH too big
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.dhMinBits = (SeosCryptoApi_Key_SIZE_DH_MAX * 8) + 1;
    TEST_NOT_SUPP(SeosTlsApi_init(&hTls, &badCfg));

    // Min size for DH too small
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.dhMinBits = (SeosCryptoApi_Key_SIZE_DH_MIN * 8) - 1;
    TEST_NOT_SUPP(SeosTlsApi_init(&hTls, &badCfg));

    // Min size for RSA too big
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.rsaMinBits = (SeosCryptoApi_Key_SIZE_RSA_MAX * 8) + 1;
    TEST_NOT_SUPP(SeosTlsApi_init(&hTls, &badCfg));

    // Min size for RSA too small
    memcpy(&badPolicy, &goodPolicy, sizeof(SeosTlsLib_Policy));
    badPolicy.rsaMinBits = (SeosCryptoApi_Key_SIZE_RSA_MIN * 8) - 1;
    TEST_NOT_SUPP(SeosTlsApi_init(&hTls, &badCfg));

    // Cert is not properly PEM encoded
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    // Invalidate the "-----BEGIN" part of the PEM encoded cert
    memset(badCfg.config.library.crypto.caCert, 0, 10);
    TEST_INVAL_PARAM(SeosTlsApi_init(&hTls, &badCfg));

    // Invalid cipher suite
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.cipherSuites[0] = 666;
    TEST_NOT_SUPP(SeosTlsApi_init(&hTls, &badCfg));

    // Too many cipher suites
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.cipherSuitesLen = SeosTlsLib_MAX_CIPHERSUITES + 1;
    TEST_INVAL_PARAM(SeosTlsApi_init(&hTls, &badCfg));

    // No ciphersuites at all
    memcpy(&badCfg, &goodCfg, sizeof(SeosTlsApi_Config));
    badCfg.config.library.crypto.cipherSuitesLen = 0;
    TEST_INVAL_PARAM(SeosTlsApi_init(&hTls, &badCfg));

    TEST_SUCCESS(SeosCryptoApi_free(goodCfg.config.library.crypto.handle));

    TEST_FINISH();
}

static void
test_OS_Tls_free_pos()
{

    SeosTlsApiH hTls;
    static SeosTlsApi_Config cfg =
    {
        .mode = SeosTlsApi_Mode_LIBRARY,
        .config.library = {
            .socket = {
                .recv = recvFunc,
                .send = sendFunc,
            },
            .crypto = {
                .caCert = TLS_HOST_CERT,
                .cipherSuites = {
                    SeosTlsLib_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                },
                .cipherSuitesLen = 1
            }
        },
    };

    TEST_START();

    TEST_SUCCESS(SeosCryptoApi_init(&cfg.config.library.crypto.handle, &cryptoCfg));

    // Simply init it and free again
    TEST_SUCCESS(SeosTlsApi_init(&hTls, &cfg));
    TEST_SUCCESS(SeosTlsApi_free(hTls));

    TEST_SUCCESS(SeosCryptoApi_free(cfg.config.library.crypto.handle));

    TEST_FINISH();
}

static void
test_OS_Tls_free_neg()
{
    TEST_START();

    // Empty context
    TEST_INVAL_PARAM(SeosTlsApi_free(NULL));

    TEST_FINISH();
}

// Test functions executed for different API modes -----------------------------

static void
test_OS_Tls_handshake_pos(
    SeosTlsApiH     hTls,
    SeosTlsApi_Mode mode)
{
    TEST_START(mode);

    // Do the handshake
    TEST_SUCCESS(SeosTlsApi_handshake(hTls));

    TEST_FINISH();
}

static void
test_OS_Tls_handshake_neg(
    SeosTlsApiH     hTls,
    SeosTlsApi_Mode mode)
{
    TEST_START(mode);

    // Handshake again on an already existing TLS session
    TEST_OP_DENIED(SeosTlsApi_handshake(hTls));

    // Without context
    TEST_INVAL_PARAM(SeosTlsApi_handshake(NULL));

    TEST_FINISH();
}

static void
test_OS_Tls_write_neg(
    SeosTlsApiH     hTls,
    SeosTlsApi_Mode mode)
{
    char* request = ECHO_STRING;
    size_t len = sizeof(request);

    TEST_START(mode);

    // No context
    TEST_INVAL_PARAM(SeosTlsApi_write(NULL, request, len));

    // No buffer
    TEST_INVAL_PARAM(SeosTlsApi_write(hTls, NULL, len));

    // Zero length write
    len = 0;
    TEST_INVAL_PARAM(SeosTlsApi_write(hTls, request, len));

    TEST_FINISH();
}

static void
test_OS_Tls_write_pos(
    SeosTlsApiH     hTls,
    SeosTlsApi_Mode mode)
{
    char request[] = ECHO_STRING;
    size_t len = sizeof(request);

    TEST_START(mode);

    /*
     * Before executing this test, a TLS sessions needs to be established
     */

    TEST_SUCCESS(SeosTlsApi_write(hTls, request, len));

    TEST_FINISH();
}

static void
test_OS_Tls_read_neg(
    SeosTlsApiH     hTls,
    SeosTlsApi_Mode mode)
{
    unsigned char buffer[1024];
    size_t len = sizeof(buffer);

    TEST_START(mode);

    // No context
    TEST_INVAL_PARAM(SeosTlsApi_read(NULL, buffer, &len));

    // No buffer
    TEST_INVAL_PARAM(SeosTlsApi_read(hTls, NULL, &len));

    // No len
    TEST_INVAL_PARAM(SeosTlsApi_read(hTls, buffer, NULL));

    // Zero length
    len = 0;
    TEST_INVAL_PARAM(SeosTlsApi_read(hTls, buffer, &len));

    TEST_FINISH();
}

static void
test_OS_Tls_read_pos(
    SeosTlsApiH     hTls,
    SeosTlsApi_Mode mode)
{
    unsigned char buffer[1024];
    const char answer[] = ECHO_STRING;
    size_t len = sizeof(buffer);

    TEST_START(mode);

    /*
     * Before executing this test, we should have sent the ECHO_STRING to the
     * echo server already as part of the write test.
     */

    len = sizeof(buffer);
    memset(buffer, 0, sizeof(buffer));
    TEST_SUCCESS(SeosTlsApi_read(hTls, buffer, &len));
    TEST_TRUE(len == sizeof(answer));
    TEST_TRUE(!memcmp(buffer, answer, len));

    TEST_FINISH();
}

static void
test_OS_Tls_reset_pos(
    SeosTlsApiH           hTls,
    SeosTlsApi_Mode       mode,
    OS_NetworkSocket_Handle_t* socket)
{
    TEST_START(mode);

    /*
     * For this test we expect the socket to be closed and the TLS session to
     * be finished as well.
     */

    // Reset the API and the socket
    TEST_SUCCESS(SeosTlsApi_reset(hTls));
    TEST_SUCCESS(resetSocket(socket));
    // Do the handshake again
    TEST_SUCCESS(SeosTlsApi_handshake(hTls));

    TEST_FINISH();
}

static void
test_OS_Tls_reset_neg(
    SeosTlsApiH           hTls,
    SeosTlsApi_Mode       mode,
    OS_NetworkSocket_Handle_t* socket)
{
    TEST_START(mode);

    TEST_INVAL_PARAM(SeosTlsApi_reset(NULL));

    TEST_FINISH();
}

static void
test_OS_Tls_mode(
    SeosTlsApiH           hTls,
    OS_NetworkSocket_Handle_t* socket)
{
    SeosTlsApi_Mode mode = SeosTlsApi_getMode(hTls);
    char desc[128];

    switch (mode)
    {
    case SeosTlsApi_Mode_LIBRARY:
        strcpy(desc, "SeosTlsApi_Mode_LIBRARY");
        break;
    case SeosTlsApi_Mode_RPC_CLIENT:
        strcpy(desc, "SeosTlsApi_Mode_RPC_CLIENT");
        break;
    default:
        TEST_TRUE(1 == 0);
    }

    Debug_LOG_INFO("Testing TLS API in %s mode:", desc);

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

    test_OS_Tls_handshake_pos(hTls, mode);
    test_OS_Tls_handshake_neg(hTls, mode);

    test_OS_Tls_write_neg(hTls, mode);
    test_OS_Tls_write_pos(hTls, mode);

    test_OS_Tls_read_neg(hTls, mode);
    test_OS_Tls_read_pos(hTls, mode);

    /*
     * Here the TLS session and socket should be closed by the server. We will
     * now re-set it with these tests to see if we can make the handshake work
     * again.
     */

    test_OS_Tls_reset_neg(hTls, mode, socket);
    test_OS_Tls_reset_pos(hTls, mode, socket);
}

// Public functions ------------------------------------------------------------

int run()
{
    SeosTlsApiH hTls;
    static OS_NetworkSocket_Handle_t socket;
    static SeosTlsApi_Config localCfg =
    {
        .mode = SeosTlsApi_Mode_LIBRARY,
        .config.library = {
            .socket = {
                .context = &socket,
                .recv = recvFunc,
                .send = sendFunc,
            },
            .flags = SeosTlsLib_Flag_DEBUG,
            .crypto = {
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
        .mode = SeosTlsApi_Mode_RPC_CLIENT,
        .config.client.dataport = tlsClientDataport,
    };

    Debug_LOG_INFO("Testing TLS API:");

    // Test init and free independent of API mode
    test_OS_Tls_init_pos();
    test_OS_Tls_init_neg();

    test_OS_Tls_free_pos();
    test_OS_Tls_free_neg();

    Debug_LOG_INFO("");

    OS_NetworkAPP_RT(NULL);

    // Test library mode
    TEST_SUCCESS(connectSocket(&socket));
    TEST_SUCCESS(SeosCryptoApi_init(&localCfg.config.library.crypto.handle,
                                    &cryptoCfg));
    TEST_SUCCESS(SeosTlsApi_init(&hTls, &localCfg));
    test_OS_Tls_mode(hTls, &socket);
    TEST_SUCCESS(SeosTlsApi_free(hTls));
    TEST_SUCCESS(SeosCryptoApi_free(localCfg.config.library.crypto.handle));
    TEST_SUCCESS(closeSocket(&socket));

    Debug_LOG_INFO("");

    TEST_SUCCESS(TlsRpcServer_init());

    // Test RPC client mode (and implicitly the RPC server side as well)
    TEST_SUCCESS(TlsRpcServer_connectSocket());
    TEST_SUCCESS(SeosTlsApi_init(&hTls, &remoteCfg));
    test_OS_Tls_mode(hTls, NULL);
    TEST_SUCCESS(SeosTlsApi_free(hTls));
    TEST_SUCCESS(TlsRpcServer_closeSocket());
    TEST_SUCCESS(TlsRpcServer_free());

    Debug_LOG_INFO("All tests successfully completed.");

    return 0;
}

///@}
