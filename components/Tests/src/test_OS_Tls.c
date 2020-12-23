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

#include "OS_Crypto.h"
#include "OS_Tls.h"
#include "OS_Network.h"
#include "OS_NetworkStackClient.h"

#include "lib_macros/Test.h"

#include <camkes.h>
#include <string.h>

#define MAX_NW_SIZE 256

// Use for read/write testing with ECHO server
#define ECHO_STRING "ThisIsATestStringPleaseSendItBackToMe!!"

// In case we need a not-NULL address to test something
#define NOT_NULL ((void*) 1)

// External API
extern OS_Error_t OS_NetworkAPP_RT(OS_Network_Context_t ctx);

// Forward declaration
static int sendFunc(void* ctx, const unsigned char* buf, size_t len);
static int recvFunc(void* ctx, unsigned char* buf, size_t len);

static OS_Crypto_Config_t cryptoCfg =
{
    .mode = OS_Crypto_MODE_LIBRARY,
    .entropy = IF_OS_ENTROPY_ASSIGN(
        entropy_rpc,
        entropy_port),
};
static OS_NetworkSocket_Handle_t socket;
static OS_Tls_Config_t localCfg =
{
    .mode = OS_Tls_MODE_LIBRARY,
    .library = {
        .socket = {
            .context = &socket,
            .recv = recvFunc,
            .send = sendFunc,
        },
        .flags = OS_Tls_FLAG_DEBUG,
        .crypto = {
            .caCerts = TLS_HOST_CERT,
            .cipherSuites = OS_Tls_CIPHERSUITE_FLAGS(
                OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        },
    }
};

// Private functions -----------------------------------------------------------

static int
sendFunc(
    void*                ctx,
    const unsigned char* buf,
    size_t               len)
{
    OS_Error_t err;
    OS_NetworkSocket_Handle_t* socket = (OS_NetworkSocket_Handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = OS_NetworkSocket_write(*socket, buf, n, &n)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("Error during socket write...error:%d", err);
        return err;
    }

    return n;
}

static int
recvFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    OS_Error_t err;
    OS_NetworkSocket_Handle_t* socket = (OS_NetworkSocket_Handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = OS_NetworkSocket_read(*socket, buf, n, &n)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("Error during socket read...error:%d", err);
        return err;
    }

    return n;
}

static OS_Error_t
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

static OS_Error_t
closeSocket(
    OS_NetworkSocket_Handle_t* socket)
{
    return OS_NetworkSocket_close(*socket);
}

static OS_Error_t
resetSocket(
    OS_NetworkSocket_Handle_t* socket)
{
    OS_Error_t err;

    if ((err = closeSocket(socket)) != OS_SUCCESS)
    {
        return err;
    }
    if ((err = connectSocket(socket)) != OS_SUCCESS)
    {
        return err;
    }

    return OS_SUCCESS;
}

// Test functions executed once ------------------------------------------------

static void
test_OS_Tls_init_pos()
{
    OS_Tls_Handle_t hTls;
    OS_Crypto_Handle_t hCrypto;
    static OS_Tls_Config_t cfgAllSuites =
    {
        .mode = OS_Tls_MODE_LIBRARY,
        .library = {
            .socket = {
                .recv = recvFunc,
                .send = sendFunc,
            },
            .crypto = {
                .caCerts = TLS_HOST_CERT,
                .cipherSuites =
                OS_Tls_CIPHERSUITE_FLAGS(
                    OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256)
            }
        },
    };
    static OS_Tls_Config_t cfgOneSuite =
    {
        .mode = OS_Tls_MODE_LIBRARY,
        .library = {
            .socket = {
                .recv = recvFunc,
                .send = sendFunc,
            },
            .crypto = {
                .caCerts = TLS_HOST_CERT,
                .cipherSuites = OS_Tls_CIPHERSUITE_FLAGS(
                    OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256)
            }
        },
    };
    static OS_Tls_Policy_t policy =
    {
        .handshakeDigests = OS_Tls_DIGEST_FLAGS(OS_Tls_DIGEST_SHA256),
        .certDigests = OS_Tls_DIGEST_FLAGS(OS_Tls_DIGEST_SHA256),
        .rsaMinBits = OS_CryptoKey_SIZE_RSA_MIN * 8,
        .dhMinBits = OS_CryptoKey_SIZE_DH_MAX * 8
    };

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&hCrypto, &cryptoCfg));
    cfgAllSuites.library.crypto.handle = hCrypto;
    cfgOneSuite.library.crypto.handle = hCrypto;

    // Test with all ciphersuites enabled
    TEST_SUCCESS(OS_Tls_init(&hTls, &cfgAllSuites));
    TEST_SUCCESS(OS_Tls_free(hTls));

    // Test with only one ciphersuite enabled
    TEST_SUCCESS(OS_Tls_init(&hTls, &cfgOneSuite));
    TEST_SUCCESS(OS_Tls_free(hTls));

    // Test with all ciphersuites and policy options
    cfgAllSuites.library.crypto.policy = &policy;
    TEST_SUCCESS(OS_Tls_init(&hTls, &cfgAllSuites));
    TEST_SUCCESS(OS_Tls_free(hTls));

    TEST_SUCCESS(OS_Crypto_free(hCrypto));

    TEST_FINISH();
}

static void
test_OS_Tls_init_neg()
{
    OS_Tls_Handle_t hTls;
    static OS_Tls_Policy_t badPolicy, goodPolicy =
    {
        .handshakeDigests = OS_Tls_DIGEST_FLAGS(OS_Tls_DIGEST_SHA256),
        .certDigests = OS_Tls_DIGEST_FLAGS(OS_Tls_DIGEST_SHA256),
        .rsaMinBits = OS_CryptoKey_SIZE_RSA_MIN * 8,
        .dhMinBits = OS_CryptoKey_SIZE_DH_MIN * 8
    };
    static OS_Tls_Config_t badCfg, goodCfg =
    {
        .mode = OS_Tls_MODE_LIBRARY,
        .library = {
            .socket = {
                .recv = recvFunc,
                .send = sendFunc,
            },
            .crypto = {
                .policy = NULL,
                .caCerts = TLS_HOST_CERT,
                .cipherSuites =
                OS_Tls_CIPHERSUITE_FLAGS(
                    OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256)
            }
        },
    };

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&goodCfg.library.crypto.handle, &cryptoCfg));

    // Provide bad mode
    memcpy(&badCfg, &goodCfg, sizeof(OS_Tls_Config_t));
    badCfg.mode = 666;
    TEST_INVAL_PARAM(OS_Tls_init(&hTls, &badCfg));

    // No RECV callback
    memcpy(&badCfg, &goodCfg, sizeof(OS_Tls_Config_t));
    badCfg.library.socket.recv = NULL;
    TEST_INVAL_PARAM(OS_Tls_init(&hTls, &badCfg));

    // No SEND callback
    memcpy(&badCfg, &goodCfg, sizeof(OS_Tls_Config_t));
    badCfg.library.socket.send = NULL;
    TEST_INVAL_PARAM(OS_Tls_init(&hTls, &badCfg));

    // No crypto context
    memcpy(&badCfg, &goodCfg, sizeof(OS_Tls_Config_t));
    badCfg.library.crypto.handle = NULL;
    TEST_INVAL_PARAM(OS_Tls_init(&hTls, &badCfg));

    memcpy(&badCfg, &goodCfg, sizeof(OS_Tls_Config_t));
    badCfg.library.crypto.policy = &badPolicy;

    // No session digest algorithm
    memcpy(&badPolicy, &goodPolicy, sizeof(OS_Tls_Policy_t));
    badPolicy.handshakeDigests = 0;
    TEST_INVAL_PARAM(OS_Tls_init(&hTls, &badCfg));

    // No signature digest algorithm
    memcpy(&badPolicy, &goodPolicy, sizeof(OS_Tls_Policy_t));
    badPolicy.certDigests = 0;
    TEST_INVAL_PARAM(OS_Tls_init(&hTls, &badCfg));

    // Min size for DH too big
    memcpy(&badPolicy, &goodPolicy, sizeof(OS_Tls_Policy_t));
    badPolicy.dhMinBits = (OS_CryptoKey_SIZE_DH_MAX * 8) + 1;
    TEST_INVAL_PARAM(OS_Tls_init(&hTls, &badCfg));

    // Min size for DH too small
    memcpy(&badPolicy, &goodPolicy, sizeof(OS_Tls_Policy_t));
    badPolicy.dhMinBits = (OS_CryptoKey_SIZE_DH_MIN * 8) - 1;
    TEST_INVAL_PARAM(OS_Tls_init(&hTls, &badCfg));

    // Min size for RSA too big
    memcpy(&badPolicy, &goodPolicy, sizeof(OS_Tls_Policy_t));
    badPolicy.rsaMinBits = (OS_CryptoKey_SIZE_RSA_MAX * 8) + 1;
    TEST_INVAL_PARAM(OS_Tls_init(&hTls, &badCfg));

    // Min size for RSA too small
    memcpy(&badPolicy, &goodPolicy, sizeof(OS_Tls_Policy_t));
    badPolicy.rsaMinBits = (OS_CryptoKey_SIZE_RSA_MIN * 8) - 1;
    TEST_INVAL_PARAM(OS_Tls_init(&hTls, &badCfg));

    // Cert is not properly PEM encoded
    memcpy(&badCfg, &goodCfg, sizeof(OS_Tls_Config_t));
    // Invalidate the "-----BEGIN" part of the PEM encoded cert
    badCfg.library.crypto.caCerts = TLS_HOST_CERT_BROKEN;
    TEST_INVAL_PARAM(OS_Tls_init(&hTls, &badCfg));

    // No ciphersuites at all
    memcpy(&badCfg, &goodCfg, sizeof(OS_Tls_Config_t));
    badCfg.library.crypto.cipherSuites = 0;
    TEST_INVAL_PARAM(OS_Tls_init(&hTls, &badCfg));

    TEST_SUCCESS(OS_Crypto_free(goodCfg.library.crypto.handle));

    TEST_FINISH();
}

static void
test_OS_Tls_free_pos()
{

    OS_Tls_Handle_t hTls;
    static OS_Tls_Config_t cfg =
    {
        .mode = OS_Tls_MODE_LIBRARY,
        .library = {
            .socket = {
                .recv = recvFunc,
                .send = sendFunc,
            },
            .crypto = {
                .caCerts = TLS_HOST_CERT,
                .cipherSuites = OS_Tls_CIPHERSUITE_FLAGS(
                    OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            }
        },
    };

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&cfg.library.crypto.handle, &cryptoCfg));

    // Simply init it and free again
    TEST_SUCCESS(OS_Tls_init(&hTls, &cfg));
    TEST_SUCCESS(OS_Tls_free(hTls));

    TEST_SUCCESS(OS_Crypto_free(cfg.library.crypto.handle));

    TEST_FINISH();
}

static void
test_OS_Tls_free_neg()
{
    TEST_START();

    // Empty context
    TEST_INVAL_PARAM(OS_Tls_free(NULL));

    TEST_FINISH();
}

// Test functions executed for different API modes -----------------------------

static void
test_OS_Tls_handshake_pos(
    OS_Tls_Handle_t hTls,
    OS_Tls_Mode_t   mode)
{
    TEST_START("i", mode);

    // Do the handshake
    TEST_SUCCESS(OS_Tls_handshake(hTls));

    TEST_FINISH();
}

static void
test_OS_Tls_handshake_neg(
    OS_Tls_Handle_t hTls,
    OS_Tls_Mode_t   mode)
{
    TEST_START("i", mode);

    // Handshake again on an already existing TLS session
    TEST_OP_DENIED(OS_Tls_handshake(hTls));

    // Without context
    TEST_INVAL_PARAM(OS_Tls_handshake(NULL));

    TEST_FINISH();
}

static void
test_OS_Tls_write_neg(
    OS_Tls_Handle_t hTls,
    OS_Tls_Mode_t   mode)
{
    char* request = ECHO_STRING;
    size_t len = sizeof(request);

    TEST_START("i", mode);

    // No context
    TEST_INVAL_PARAM(OS_Tls_write(NULL, request, &len));

    // No buffer
    TEST_INVAL_PARAM(OS_Tls_write(hTls, NULL, &len));

    // Zero length write
    len = 0;
    TEST_INVAL_PARAM(OS_Tls_write(hTls, request, &len));

    TEST_FINISH();
}

static void
test_OS_Tls_write_pos(
    OS_Tls_Handle_t hTls,
    OS_Tls_Mode_t   mode)
{
    char request[] = ECHO_STRING;
    size_t len = sizeof(request);

    TEST_START("i", mode);

    /*
     * Before executing this test, a TLS sessions needs to be established
     */

    TEST_SUCCESS(OS_Tls_write(hTls, request, &len));
    TEST_TRUE(len == sizeof(request));

    TEST_FINISH();
}

static void
test_OS_Tls_read_neg(
    OS_Tls_Handle_t hTls,
    OS_Tls_Mode_t   mode)
{
    unsigned char buffer[1024];
    size_t len = sizeof(buffer);

    TEST_START("i", mode);

    // No context
    TEST_INVAL_PARAM(OS_Tls_read(NULL, buffer, &len));

    // No buffer
    TEST_INVAL_PARAM(OS_Tls_read(hTls, NULL, &len));

    // No len
    TEST_INVAL_PARAM(OS_Tls_read(hTls, buffer, NULL));

    // Zero length
    len = 0;
    TEST_INVAL_PARAM(OS_Tls_read(hTls, buffer, &len));

    TEST_FINISH();
}

static void
test_OS_Tls_read_pos(
    OS_Tls_Handle_t hTls,
    OS_Tls_Mode_t   mode)
{
// This is an arbitrary number, just to do the read in a few chunks and not in one swoop
#define CHUNK_SIZE 4
    unsigned char buffer[1024];
    const char answer[] = ECHO_STRING;
    size_t read, total;

    TEST_START("i", mode);

    /*
     * Before executing this test, we should have sent the ECHO_STRING to the
     * echo server already as part of the write test.
     */

    memset(buffer, 0, sizeof(buffer));

    total = 0;
    while ((total + CHUNK_SIZE) < sizeof(buffer))
    {
        read = CHUNK_SIZE;
        if (total < sizeof(answer))
        {
            TEST_SUCCESS(OS_Tls_read(hTls, buffer + total, &read));
        }
        else
        {
            // If we try reading beyond what is available, we should get the
            // message that the connection is closed.
            TEST_CONN_CLOSED(OS_Tls_read(hTls, buffer + total, &read));
            break;
        }
        total += read;
    }

    TEST_TRUE(total == sizeof(answer));
    TEST_TRUE(!memcmp(buffer, answer, total));

    TEST_FINISH();
}

static void
test_OS_Tls_reset_pos(
    OS_Tls_Handle_t            hTls,
    OS_Tls_Mode_t              mode,
    OS_NetworkSocket_Handle_t* socket)
{
    TEST_START("i", mode);

    /*
     * For this test we expect the socket to be closed and the TLS session to
     * be finished as well.
     */

    // Reset the API and the socket
    TEST_SUCCESS(OS_Tls_reset(hTls));
    TEST_SUCCESS(resetSocket(socket));
    // Do the handshake again
    TEST_SUCCESS(OS_Tls_handshake(hTls));

    TEST_FINISH();
}

static void
test_OS_Tls_reset_neg(
    OS_Tls_Handle_t            hTls,
    OS_Tls_Mode_t              mode,
    OS_NetworkSocket_Handle_t* socket)
{
    TEST_START("i", mode);

    TEST_INVAL_PARAM(OS_Tls_reset(NULL));

    TEST_FINISH();
}

static void
test_OS_Tls_mode(
    OS_Tls_Handle_t            hTls,
    OS_NetworkSocket_Handle_t* socket)
{
    OS_Tls_Mode_t mode = OS_Tls_getMode(hTls);
    char desc[128];

    switch (mode)
    {
    case OS_Tls_MODE_LIBRARY:
        strcpy(desc, "OS_Tls_MODE_LIBRARY");
        break;
    case OS_Tls_MODE_CLIENT:
        strcpy(desc, "OS_Tls_MODE_CLIENT");
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

static void
init_network_client_api()
{
    static OS_NetworkStackClient_SocketDataports_t config;
    static OS_Dataport_t dataport = OS_DATAPORT_ASSIGN(NwAppDataPort);

    config.number_of_sockets = 1;

    config.dataport = &dataport;
    OS_NetworkStackClient_init(&config);
}

// Public functions ------------------------------------------------------------

int run()
{
    init_network_client_api();

    OS_Tls_Handle_t hTls;

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
    TEST_SUCCESS(OS_Crypto_init(&localCfg.library.crypto.handle, &cryptoCfg));
    TEST_SUCCESS(OS_Tls_init(&hTls, &localCfg));
    test_OS_Tls_mode(hTls, &socket);
    TEST_SUCCESS(OS_Tls_free(hTls));
    TEST_SUCCESS(OS_Crypto_free(localCfg.library.crypto.handle));
    TEST_SUCCESS(closeSocket(&socket));

    Debug_LOG_INFO("All tests successfully completed.");

    return 0;
}

///@}
