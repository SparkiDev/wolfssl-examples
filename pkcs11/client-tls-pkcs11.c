/* client-tls-ecdhe.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/wc_pkcs11.h>

#define DEFAULT_PORT 11111

#define CERT_FILE "../certs/ca-cert.pem"

#define ECC_FILE    "../certs/client-cert.pem"
#define PRIV_KEY_ID {0x00, 0x03}
#define CIPHER_LIST "ECDHE-ECDSA-CHACHA20-POLY1305"



int client_tls(int devId, Pkcs11Token* token, const char* ipAddr)
{
    int                sockfd;
    struct sockaddr_in servAddr;
    char               buff[256];
    char*              p;
    size_t             len;
    int                ret;
    unsigned char      privKeyId[] = PRIV_KEY_ID;

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;



    /* Initialize wolfSSL */
    wolfSSL_Init();



    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        return -1;
    }



    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return -1;
    }

    if (wolfSSL_CTX_SetDevId(ctx, devId) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return -1;
    }

    /* Load client certificates into WOLFSSL_CTX */
    if (wolfSSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL)
        != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CERT_FILE);
        return -1;
    }

    /* Load client ecc certificates into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_certificate_chain_file(ctx, ECC_FILE) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                ECC_FILE);
        return -1;
    }

    /* Load client key into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_PrivateKey_id(ctx, privKeyId, sizeof(privKeyId), devId,
            2048/8) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to set id.\n");
        return -1;
    }



    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;             /* using IPv4      */
    servAddr.sin_port   = htons(DEFAULT_PORT); /* on DEFAULT_PORT */

    /* Get the server IPv4 address from the command line call */
    if (inet_pton(AF_INET, ipAddr, &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        return -1;
    }



    /* Connect to the server */
    if (connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr))
        == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        return -1;
    }


    /* Create a WOLFSSL object */
    if ((ret = wc_Pkcs11Token_Open(token, 1)) != 0) {
        fprintf(stderr, "ERROR: failed to open session on token (%d)\n", ret);
        return -1;
    }


    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        return -1;
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(ssl, sockfd);

    /* Connect to wolfSSL on the server side */
    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        return -1;
    }



    /* Get a message for the server from stdin */
    printf("Message for server: ");
    memset(buff, 0, sizeof(buff));
    p = fgets(buff, sizeof(buff), stdin);
    (void)p;
    len = strnlen(buff, sizeof(buff));

    /* Send the message to the server */
    if (wolfSSL_write(ssl, buff, len) != len) {
        fprintf(stderr, "ERROR: failed to write\n");
        return -1;
    }



    /* Read the server data into our buff array */
    memset(buff, 0, sizeof(buff));
    if (wolfSSL_read(ssl, buff, sizeof(buff)-1) == -1) {
        fprintf(stderr, "ERROR: failed to read\n");
        return -1;
    }

    /* Print to stdout any data the server sends */
    printf("Server: %s\n", buff);



    /* Cleanup and return */
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
    wc_Pkcs11Token_Close(token);
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
    close(sockfd);          /* Close the connection to the server       */
    return 0;               /* Return reporting a success               */
}

int main(int argc, char** argv)
{
    int ret;
    const char* ipAddr;
    const char* library;
    const char* slot;
    const char* tokenName;
    const char* userPin;
    Pkcs11Dev dev;
    Pkcs11Token token;
    int slotId;
    int devId = 1;

    if (argc != 6) {
        fprintf(stderr, "Usage: %s-tls-pkcs11-ecc <IPv4 address> <libname> "
                        "<slot> <tokenname> <userpin>\n", argv[0]);
        return 1;
    }

    ipAddr = argv[1];
    library = argv[2];
    slot = argv[3];
    tokenName = argv[4];
    userPin = argv[5];
    slotId = atoi(slot);

#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif
    wolfCrypt_Init();

    ret = wc_Pkcs11_Initialize(&dev, library, NULL);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize PKCS#11 library\n");
        ret = 2;
    }
    if (ret == 0) {
        ret = wc_Pkcs11Token_Init(&token, &dev, slotId, tokenName,
                                  (byte*)userPin, strlen(userPin));
        if (ret != 0) {
            fprintf(stderr, "Failed to initialize PKCS#11 token\n");
            ret = 2;
        }
        if (ret == 0) {
            ret = wc_CryptoDev_RegisterDevice(devId, wc_Pkcs11_CryptoDevCb,
                                              &token);
            if (ret != 0) {
                fprintf(stderr, "Failed to register PKCS#11 token\n");
                ret = 2;
            }
            if (ret == 0) {
            #if !defined(WOLFCRYPT_ONLY)
                ret = client_tls(devId, &token, ipAddr);
                if (ret != 0)
                    ret = 1;
            #endif
            }
            wc_Pkcs11Token_Final(&token);
        }
        wc_Pkcs11_Finalize(&dev);
    }

    wolfCrypt_Cleanup();

    return ret;
}
