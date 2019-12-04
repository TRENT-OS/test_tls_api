/*
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include <string.h>

#include "TlsRpcServer.h"

#include "seos_nw_api.h"

#include <camkes.h>
#include <string.h>

#define MAX_NW_SIZE 2048

extern seos_err_t Seos_NwAPP_RT(Seos_nw_context ctx);

static int
sendFunc(void*                  ctx,
         const unsigned char*   buf,
         size_t                 len);

static int
recvFunc(void*                  ctx,
         unsigned char*         buf,
         size_t                 len);

static int
entropyFunc(void*               ctx,
            unsigned char*      buf,
            size_t              len);

static SeosTlsApi_Config serverCfg =
{
    .mode = SeosTlsApi_Mode_AS_RPC_SERVER,
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
            .caCert = "-----BEGIN CERTIFICATE-----\r\n"                            \
            "MIIElDCCA3ygAwIBAgIQAf2j627KdciIQ4tyS8+8kTANBgkqhkiG9w0BAQsFADBh\r\n" \
            "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n" \
            "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\r\n" \
            "QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaME0xCzAJBgNVBAYTAlVT\r\n" \
            "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg\r\n" \
            "U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\r\n" \
            "ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83\r\n" \
            "nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd\r\n" \
            "KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f\r\n" \
            "/ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX\r\n" \
            "kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0\r\n" \
            "/RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8C\r\n" \
            "AQAwDgYDVR0PAQH/BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYY\r\n" \
            "aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6\r\n" \
            "Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwN6A1\r\n" \
            "oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RD\r\n" \
            "QS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v\r\n" \
            "d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFA+AYRyCMWHVLyjnjUY4tCzh\r\n" \
            "xtniMB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA0GCSqGSIb3DQEB\r\n" \
            "CwUAA4IBAQAjPt9L0jFCpbZ+QlwaRMxp0Wi0XUvgBCFsS+JtzLHgl4+mUwnNqipl\r\n" \
            "5TlPHoOlblyYoiQm5vuh7ZPHLgLGTUq/sELfeNqzqPlt/yGFUzZgTHbO7Djc1lGA\r\n" \
            "8MXW5dRNJ2Srm8c+cftIl7gzbckTB+6WohsYFfZcTEDts8Ls/3HB40f/1LkAtDdC\r\n" \
            "2iDJ6m6K7hQGrn2iWZiIqBtvLfTyyRRfJs8sjX7tN8Cp1Tm5gr8ZDOo0rwAhaPit\r\n" \
            "c+LJMto4JQtV05od8GiG7S5BNO98pVAdvzr508EIDObtHopYJeS4d60tbvVS3bR0\r\n" \
            "j6tJLp07kzQoH3jOlOrHvdPJbRzeXDLz\r\n"                                 \
            "-----END CERTIFICATE-----\r\n",
            .cipherSuites = {
                SeosTlsLib_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            },
            .cipherSuitesLen = 1
        }
    }
};

static const SeosCrypto_Callbacks cryptoConfig =
{
    .malloc     = malloc,
    .free       = free,
    .entropy    = entropyFunc
};

static SeosTlsApi_Context       tlsContext;
static SeosCrypto               seosCrypto;
static SeosCryptoCtx*           cryptoContext;
static seos_socket_handle_t     socket;
static TlsRpcServer_Config      config;

// Private static functions ----------------------------------------------------

static int
sendFunc(void*                  ctx,
         const unsigned char*   buf,
         size_t                 len)
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
recvFunc(void*          ctx,
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
entropyFunc(void*           ctx,
            unsigned char*  buf,
            size_t          len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

// Public functions ------------------------------------------------------------

seos_err_t
TlsRpcServer_init(SeosTlsRpcServer_Handle*  ctx,
                  TlsRpcServer_Config       cfg)
{
    seos_err_t err;
    seos_nw_client_struct socketCfg =
    {
        .domain = SEOS_AF_INET,
        .type   = SEOS_SOCK_STREAM,
        .name   = config.ip,
    };

    printf("TlsRpcServer is connecting to: %s:%i\n", cfg.ip, cfg.port);

    memcpy(&config, &cfg, sizeof(TlsRpcServer_Config));
    socketCfg.port = cfg.port;
    err = Seos_client_socket_create(NULL, &socketCfg, &socket);
    Debug_ASSERT(SEOS_SUCCESS == err);

    err = SeosCrypto_init(&seosCrypto, &cryptoConfig, NULL);
    Debug_ASSERT(SEOS_SUCCESS == err);
    cryptoContext = SeosCrypto_TO_SEOS_CRYPTO_CTX(&seosCrypto);

    serverCfg.config.server.dataport               = tlsServerDataport;
    serverCfg.config.server.library.socket.context = &socket;
    serverCfg.config.server.library.crypto.context = cryptoContext;

    err = SeosTlsApi_init(&tlsContext, &serverCfg);
    Debug_ASSERT(SEOS_SUCCESS == err);

    *ctx = &tlsContext;

    return 0;
}

int run()
{
    Debug_PRINTF("Starting TlsRpcServer networking...\n");

    Seos_NwAPP_RT(NULL);

    return 0;
}

seos_err_t
TlsRpcServer_free()
{
    seos_err_t err;

    err = SeosTlsApi_free(&tlsContext);
    Debug_ASSERT(SEOS_SUCCESS == err);

    err = SeosCrypto_free(cryptoContext);
    Debug_ASSERT(SEOS_SUCCESS == err);

    return 0;
}