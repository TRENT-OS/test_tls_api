/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * SEOS TLS test configuration
 *
 */
#pragma once

// IP address of jenkins host so we can reach our own TLS Server we set up there
#define TLS_HOST_IP     "10.0.0.1"
#define TLS_HOST_PORT   8888
// Certificate of our own TLS server
#define TLS_HOST_CERT \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIDuzCCAqOgAwIBAgIUIlFP3QticKvSug25KJUVB4mqdlswDQYJKoZIhvcNAQEL\r\n" \
    "BQAwbTELMAkGA1UEBhMCREUxEDAOBgNVBAgMB0JhdmFyaWExDzANBgNVBAcMBk11\r\n" \
    "bmljaDEcMBoGA1UECgwTSGVuc29sZHQgQ3liZXIgR21iSDELMAkGA1UECwwCQ1Mx\r\n" \
    "EDAOBgNVBAMMB0NJIFRlc3QwHhcNMjAwMjAzMDk1NTIyWhcNMzAwMTMxMDk1NTIy\r\n" \
    "WjBtMQswCQYDVQQGEwJERTEQMA4GA1UECAwHQmF2YXJpYTEPMA0GA1UEBwwGTXVu\r\n" \
    "aWNoMRwwGgYDVQQKDBNIZW5zb2xkdCBDeWJlciBHbWJIMQswCQYDVQQLDAJDUzEQ\r\n" \
    "MA4GA1UEAwwHQ0kgVGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\r\n" \
    "AOkdsC9ckEQcFHQcQ3LOGFQB+2DQ+GbzHnE6UxjUD8HNJjkpGBgOvF/VLBl02wlu\r\n" \
    "SzxACwZ3W9AhXfwJ972vSqYipj0RQyzDy2Nh5VtNPAUNQePwsIku4gpT5KNXkPt/\r\n" \
    "zU1KdQKKyWx/VjmHUxidtAr5yttqOmhQ1fZ+buYMPO7ohaHSd+QX2Xv5W6QyA6wD\r\n" \
    "YYNt0TE70dJ/Ww5luI1WYFwh9vNA/tiJTPVv5kRdx2/GsOSYON2esF6lIgPTKD1k\r\n" \
    "E/zjAOWer3eMPS4rx59F/W0xxSvs71sOhMDPOUp2+82a8qDsOomwypWLz/vqcaxD\r\n" \
    "91mEw0JorGcesqbO+qCM97ECAwEAAaNTMFEwHQYDVR0OBBYEFAA5WYY71fbT6U+l\r\n" \
    "arVlDdmlbL4kMB8GA1UdIwQYMBaAFAA5WYY71fbT6U+larVlDdmlbL4kMA8GA1Ud\r\n" \
    "EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJtNxhpoL3+UIx7utP/fwLuR\r\n" \
    "Qb++yzC7GPtTysWztXfrm+8SA44o9MYjqJC6Xr0m67QVh7dmPmgCevPFpuAZJbea\r\n" \
    "r+KkAnILyvoxl/p1RmEQXMNQ2/xd3p0FtVZ9FBQX0LdmvvFex1zB1I8ykHvKSu40\r\n" \
    "jvPtrmG0XDDz1aNoLcRWfltVufAQP8QPbZ0xW79dKOqYdV4kV7Txd3pCRddLQQQj\r\n" \
    "b72aCDbgGcHYm4Po+AgYWs4pYP62x7T44xdUYR1QuTb/3J5RMgIcvzngZdD64IFI\r\n" \
    "geBoqyeoBvba6XuFFX7QIX6c39n/Is4aU98GsQHeGY9BCXx9PhNojDKfysyvPGI=\r\n" \
    "-----END CERTIFICATE-----\r\n"
