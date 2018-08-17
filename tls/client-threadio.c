/* client-tls.c
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

#define DEFAULT_PORT 11111

#define CERT_FILE "../certs/ca-cert.pem"

/* HTTP index.html page request */
#define GET_PAGE "GET /index.html HTTP/1.0\r\n\r\n"
#define GET_PAGE_SZ  28

#define MIN_READ_SIZE   (1 << 7)
#define CEIL_128(v)     ((((v) + (1 << 7) - 1) >> 7) << 7)
#define PACKET_SIZE     (1500 - 20)


/* State of underlying connection */
enum TcpIpConnectionState {
    NONE,
    CONNECTED,
    DISCONNECT,
    DISCONNECTED
};

/* State of SSL/TLS connection */
enum ConnObj_ConnectionState {
    SSL_NONE,
    SSL_CONNECTING,
    SSL_WRITE,
    SSL_READ,
    SSL_DISCONNECT,
    SSL_DISCONNECTED
};


/* SSL/TLS data
 * Read data is accumulated into growing and shrinking buffer.
 */
typedef struct SslData {
    WOLFSSL* ssl;
    int      state;

    byte*    data;
    int      len;
    int      max;
} SslData;

typedef struct Conn_Obj Conn_Obj;
typedef struct Conn_Data Conn_Data;
typedef int (*ConnReadCb)(byte* buf, int sz, void* ctx);


/* Underlying connection data */
struct Conn_Data {
    const char* addr;
    int         sockfd;
    int         state;

    ConnReadCb  readCb;
    void*       readCbCtx;

    Conn_Data*  next;
};

/* Connection context - holds data for all connections
 * Only one read and write packet for all connections.
 * Emulates reading/writing single packets off/onto the wire.
 *
 * Write mutex used to ensure only one SSL/TLS connection puts data into
 * a write packet at once.
 * Write connection is the data identifying where to write packet.
 *
 * Underlying I/O is performed in a separate thread.
 */
typedef struct Conn_Ctx {
    pthread_t       tid;

    byte            readPacket[PACKET_SIZE];
    int             readLen;

    byte            writePacket[PACKET_SIZE];
    int             writeLen;
    Conn_Data*      writeConn;
    pthread_mutex_t writeMutex;

    Conn_Data*      connData;
    int             cnt;
} Conn_Ctx;

/* Connection object - data for an SSL/TLS connection
 * Read mutex required for copying data from read packet to SSL/TLS data.
 */
struct Conn_Obj
{
    Conn_Ctx*       connCtx;
    Conn_Data*      connData;
    pthread_mutex_t readMutex;
    SslData         sslData;
};


static int ConnObj_ReadCb(byte* buf, int sz, void* ctx);


/* Create new connection data */
static int ConnData_New(Conn_Ctx* connCtx, char* addr, ConnReadCb readCb,
                        void* readCbCtx, Conn_Data** newConnData)
{
    Conn_Data* connData;

    connData = malloc(sizeof(*connData));
    if (connData == NULL)
        return -1;
    memset(connData, 0, sizeof(*connData));

    connData->addr = addr;
    connData->readCb = readCb;
    connData->readCbCtx = readCbCtx;
    /* Put connection data into chain in context */
    connData->next = connCtx->connData;
    connCtx->connData = connData;
    connCtx->cnt++;

    *newConnData = connData;

    return 0;
}

/* Free new connection data */
static void ConnData_Free(Conn_Data* connData)
{
    free(connData);
}

/* Connect to TCP/IP address.
 *
 * Address string of form: <IPv4 Address>[:<port>]
 * If port not specified then use: DEFAULT_PORT.
 */
static int ConnData_Connect(Conn_Data* connData)
{
    struct sockaddr_in servAddr;
    const char*        a = connData->addr;
    uint32_t           port;
    char               address[28];
    int                i;

    port = DEFAULT_PORT;
    for (i = 0; i < sizeof(address) - 1 && a[i] != ':' && a[i] != '\0'; i++)
        address[i] = a[i];
    address[i] = '\0';
    if (a[i] == ':')
        port = atoi(&a[i + 1]);


    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((connData->sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        return -1;
    }


    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;             /* using IPv4      */
    servAddr.sin_port   = htons(port);

    /* Get the server IPv4 address from the command line call */
    if (inet_pton(AF_INET, address, &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        return -1;
    }


    /* Connect to the server */
    if (connect(connData->sockfd, (struct sockaddr*)&servAddr,
                                                     sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        return -1;
    }

    fprintf(stderr, "Connected: %s\n", a);

    return 0;
}

/* Return the IPv4 adress string of the connection */
static const char* ConnData_Address(Conn_Data* connData)
{
    return connData->addr;
}

/* Check whether underlying connection is disconnected. */
static int ConnData_IsDisconnected(Conn_Data* connData)
{
    return connData->state >= DISCONNECT;
}
/* Disconnect underlying connection. */
static void ConnDisconnect(Conn_Data* connData)
{
    connData->state = DISCONNECT;
}


/* Create a new connection context */
static int ConnCtx_New(Conn_Ctx** newConnCtx)
{
    Conn_Ctx* connCtx;

    connCtx = malloc(sizeof(Conn_Ctx));
    if (connCtx == NULL)
        return -1;
    memset(connCtx, 0, sizeof(*connCtx));
    pthread_mutex_init(&connCtx->writeMutex, NULL);

    *newConnCtx = connCtx;

    return 0;
}

/* Free the connection context */
static void ConnCtx_Free(Conn_Ctx* connCtx)
{
    Conn_Data* conn;

    for (conn = connCtx->connData; conn != NULL; conn = connCtx->connData) {
        connCtx->connData = conn->next;
        ConnData_Free(conn);
    }
    free(connCtx);
}

/* Cleanup connection context */
static void ConnCtx_Finish(Conn_Ctx* connCtx)
{
    if (connCtx == NULL)
        return;

    pthread_join(connCtx->tid, NULL);
}

/* Put bytes to send into packet if empty or already has data from
 * this connection.
 *
 * Use locking to ensure only one object sets bytes into packet at a time
 * and underlying connection doesn't send until finished.
 */
static int ConnCtx_Write(Conn_Ctx* connCtx, Conn_Data* connData, char* buf,
                         int sz)
{
    int       len = 0;

    if (connCtx->writeLen != 0 && connCtx->writeConn != connData)
        return 0;

    pthread_mutex_lock(&connCtx->writeMutex);

    if (connCtx->writeLen == 0 || connCtx->writeConn == connData) {
        connCtx->writeConn = connData;

        len = sizeof(connCtx->writePacket) - connCtx->writeLen;
        if (len > sz)
            len = sz;
        memcpy(connCtx->writePacket + connCtx->writeLen, buf, len);

        connCtx->writeLen += len;
    }

    pthread_mutex_unlock(&connCtx->writeMutex);

    return len;
}

/* Read data from an open connection. */
static void ConnCtx_Recv(Conn_Ctx* connCtx, fd_set rfds)
{
    Conn_Data* conn;

    for (conn = connCtx->connData; conn != NULL; conn = conn->next) {
        if (!ConnData_IsDisconnected(conn)) {
            if (FD_ISSET(conn->sockfd, &rfds))
                break;
        }
    }

    /* Receive a packet */
    connCtx->readLen = recv(conn->sockfd, connCtx->readPacket,
                            sizeof(connCtx->readPacket), 0);
    if (connCtx->readLen <= 0)
        ConnDisconnect(conn);
    else {
        if (conn->readCb(connCtx->readPacket, connCtx->readLen,
                                        conn->readCbCtx) != connCtx->readLen) {
            ConnDisconnect(conn);
        }
        connCtx->readLen = 0;
    }
}

/* Write data to the connection.
 *
 * Open the connection if it isn't available.
 */
static void ConnCtx_Send(Conn_Ctx* connCtx)
{
    Conn_Data* connData;
    int        ret;

    pthread_mutex_lock(&connCtx->writeMutex);

    connData = connCtx->writeConn;

    if (connData->state == NONE) {
        if (ConnData_Connect(connData) < 0) {
            connData->state = DISCONNECTED;
            return;
        }
        else
            connData->state = CONNECTED;
    }

    ret = send(connData->sockfd, connCtx->writePacket, connCtx->writeLen, 0);
    if (ret < 0)
        ConnDisconnect(connData);
    connCtx->writeLen = 0;

    pthread_mutex_unlock(&connCtx->writeMutex);
}

/* I/O thread that performs underlying connection communication. */
static void* ConnCtx_Thread(void* args)
{
    Conn_Ctx*  connCtx = (Conn_Ctx*)args;
    int        ret;
    int        cnt;
    Conn_Data* conn;

    while (1) {
        fd_set         rfds;
        struct timeval tv;
        int            maxfd = 0;

        FD_ZERO(&rfds);
        cnt = 0;

        /* Check each connection that is open */
        for (conn = connCtx->connData; conn != NULL; conn = conn->next) {
            if (ConnData_IsDisconnected(conn))
                cnt++;
            else if (conn->state != NONE) {
                FD_SET(conn->sockfd, &rfds);
                if (conn->sockfd > maxfd)
                    maxfd = conn->sockfd;
            }
        }
        if (cnt == connCtx->cnt)
            break;

        /* Try to receive for 1 millisecond. */
        tv.tv_sec = 0;
        tv.tv_usec = 100;

        if (connCtx->readLen == 0) {
            ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        }
        else {
            usleep(100);
            ret = 0;
        }
        if (ret > 0)
            ConnCtx_Recv(connCtx, rfds);
        else if (ret < 0)
            break;
        else if (connCtx->writeLen > 0)
            ConnCtx_Send(connCtx);
    }

    /* Close all connections. */
    for (conn = connCtx->connData; conn != NULL; conn = conn->next) {
        close(conn->sockfd);
        conn->state = DISCONNECTED;
    }
    fprintf(stderr, "Connections closed\n");

    return NULL;
}

/* Start the I/O thread */
static void ConnCtx_Start(Conn_Ctx* connCtx)
{
    pthread_create(&connCtx->tid, 0, ConnCtx_Thread, connCtx);
}


/* Create a new connection object with the IPv4 address string */
static int ConnObj_New(Conn_Ctx* connCtx, char* addr, Conn_Obj* connObj)
{
    memset(connObj, 0, sizeof(*connObj));
    if (ConnData_New(connCtx, addr, ConnObj_ReadCb, (void*)connObj,
                     &connObj->connData) < 0) {
        return -1;
    }
    connObj->connCtx = connCtx;
    pthread_mutex_init(&connObj->readMutex, NULL);

    return 0;
}

/* Free a connection object */
static void ConnObj_Free(Conn_Obj* connObj)
{
    if (connObj != NULL) {
        if (connObj->sslData.data != NULL)
            free(connObj->sslData.data);
    }
}

/* Create an SSL/TLS connection with connection object */
static int ConnObj_Connect(Conn_Obj* connObj, WOLFSSL_CTX* ctx)
{
    WOLFSSL* ssl = connObj->sslData.ssl;

    connObj->sslData.state = SSL_CONNECTING;

    /* Connect to wolfSSL on the server side */
    while (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        if (ConnData_IsDisconnected(connObj->connData)) {
            fprintf(stderr, "ERROR: socket not available\n");
            return -1;
        }
        if (wolfSSL_want_read(ssl) || wolfSSL_want_write(ssl)) {
            /* no error, just non-blocking. Carry on. */
            usleep(100);
            continue;
        }
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        return -1;
    }

    fprintf(stderr, "SSL connection established %s\n",
            ConnData_Address(connObj->connData));
    connObj->sslData.state = SSL_WRITE;
    return 0;
}

/* Write and read from the connection objects */
static int ConnObjs_WriteRead(Conn_Obj* connObj, int cnt)
{
    char buff[256];
    int  done = 0;
    int  i;

    while (done < cnt) {
        done = 0;
        for (i = 0; i < cnt; i++) {
            switch (connObj[i].sslData.state) {
            case SSL_DISCONNECTED:
                done++;
                continue;

            case SSL_WRITE:
                /* Send the message to the server */
                if (wolfSSL_write(connObj[i].sslData.ssl, GET_PAGE,
                                                 GET_PAGE_SZ) == GET_PAGE_SZ) {
                    connObj[i].sslData.state = SSL_READ;
                }
                else if (!wolfSSL_want_write(connObj[i].sslData.ssl)) {
                    fprintf(stderr, "ERROR: failed to write\n");
                    connObj[i].sslData.state = SSL_DISCONNECT;
                    ConnDisconnect(connObj[i].connData);
                }
                break;

            case SSL_READ:
                if (wolfSSL_read(connObj[i].sslData.ssl, buff,
                                                         sizeof(buff)-1) > 0) {
                    printf("Server: %s\n%s\n",
                           ConnData_Address(connObj[i].connData),
                           buff);
                    connObj[i].sslData.state = SSL_WRITE;
                    ConnDisconnect(connObj[i].connData);
                }
                else if (!wolfSSL_want_read(connObj[i].sslData.ssl)) {
                    fprintf(stderr, "ERROR: failed to read\n");
                    connObj[i].sslData.state = SSL_DISCONNECT;
                    ConnDisconnect(connObj[i].connData);
                }
                break;

            default:
                break;
            }

            if (ConnData_IsDisconnected(connObj[i].connData)) {
                fprintf(stderr, "SSL connection closed: %s\n",
                        ConnData_Address(connObj[i].connData));
                connObj[i].sslData.state = SSL_DISCONNECTED;
            }
        }
        usleep(100);
    }

    return 0;
}

/* Append the read bytes into read data buffer.
 *
 * Called by underlying connection.
 */
static int ConnObj_ReadCb(byte* buf, int sz, void* ctx)
{
    Conn_Obj* obj = (Conn_Obj*)ctx;
    SslData*  sslData = &obj->sslData;

    pthread_mutex_lock(&obj->readMutex);

    if (sslData->len + sz > sslData->max) {
        int len = CEIL_128(sslData->len + sz);
        byte* p = realloc(sslData->data, len);
        if (p == NULL) {
            fprintf(stderr, "ERROR: memory allocation failed\n");
            return -1;
        }
        sslData->data = p;
        sslData->max = len;
    }
    XMEMCPY(sslData->data + sslData->len, buf, sz);
    sslData->len += sz;

    pthread_mutex_unlock(&obj->readMutex);

    return sz;
}



/* Client send callback - try to put bytes into write packet */
static int WolfSSL_Send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    Conn_Obj* connObj = (Conn_Obj*)ctx;

    return ConnCtx_Write(connObj->connCtx, connObj->connData, buf, sz);
}


/* Client recv callback - return any read data. */
static int WolfSSL_Recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    Conn_Obj* connObj = (Conn_Obj*)ctx;
    SslData*  sslData = &connObj->sslData;

    if (sslData->len == 0)
        return WOLFSSL_CBIO_ERR_WANT_READ;

    pthread_mutex_lock(&connObj->readMutex);

    if (sz > sslData->len)
        sz = sslData->len;
    XMEMCPY(buf, sslData->data, sz);
    if (sslData->len != 0) {
        XMEMMOVE(sslData->data, sslData->data + sz, sslData->len - sz);
    }
    sslData->len -= sz;
    if (sslData->len < MIN_READ_SIZE && sslData->max > MIN_READ_SIZE) {
        byte* p = realloc(sslData->data, MIN_READ_SIZE);
        if (p != NULL) {
            sslData->data = p;
            sslData->max = MIN_READ_SIZE;
        }
    }

    pthread_mutex_unlock(&connObj->readMutex);

    return sz;
}

/* Initialize wolfSSL */
int WolfSSL_Init(WOLFSSL_CTX** newCtx)
{
    WOLFSSL_CTX* ctx;

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
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

    /* Use custom read and write functions */
    wolfSSL_CTX_SetIOSend(ctx, WolfSSL_Send);
    wolfSSL_CTX_SetIORecv(ctx, WolfSSL_Recv);

    *newCtx = ctx;

    return 0;
}

/* Cleanup wolfSSL conections */
void WolfSSL_Cleanup(WOLFSSL_CTX* ctx, int cnt)
{
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
}

/* Initialize wolfSSL connections */
int WolfSSL_InitObjs(WOLFSSL_CTX* ctx, Conn_Obj* connObj, int cnt)
{
    WOLFSSL*     ssl;
    int          i;

    for (i = 0; i < cnt; i++) {
        /* Create a WOLFSSL object */
        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
            return -1;
        }
        connObj[i].sslData.ssl = ssl;

        /* make wolfSSL object nonblocking */
        wolfSSL_set_using_nonblock(ssl, 1);

        /* Set the SSL object specific I/O data */
        wolfSSL_SetIOReadCtx(ssl, (void*)&connObj[i]);
        wolfSSL_SetIOWriteCtx(ssl, (void*)&connObj[i]);
    }

    return 0;
}

/* Cleanup the connection objects. */
void WolfSSL_CleanupObjs(WOLFSSL_CTX* ctx, Conn_Obj* connObj, int cnt)
{
    int i;

    (void)ctx;

    for (i = 0; i < cnt; i++) {
        wolfSSL_free(connObj[i].sslData.ssl);
        connObj[i].sslData.ssl = NULL;
    }
}


int main(int argc, char** argv)
{
    WOLFSSL_CTX* ctx;
    Conn_Ctx*    connCtx = NULL;
    Conn_Obj*    obj;
    int          i, cnt;


    /* Check for proper calling convention */
    if (argc < 2) {
        printf("usage: %s (<IPv4 address>[:<port>])+\n", argv[0]);
        return 0;
    }
    cnt = argc - 1;


    /* Allocate array of object pointers */
    obj = malloc(sizeof(*obj) * cnt);
    if (obj == NULL)
        return 1;

    /* Initialize connections */
    if (ConnCtx_New(&connCtx) < 0)
        return 1;

    for (i = 0; i < cnt; i++) {
        if (ConnObj_New(connCtx, argv[i + 1], &obj[i]) < 0)
            return 1;
    }

    /* Start underlying connection thread. */
    ConnCtx_Start(connCtx);

    if (WolfSSL_Init(&ctx) < 0)
        return 1;

    if (WolfSSL_InitObjs(ctx, obj, cnt) < 0)
        return 1;

    /* Perform SSL connection consecutively - uses lots of memory */
    for (i = 0; i < cnt; i++) {
        if (ConnObj_Connect(&obj[i], ctx) < 0)
            break;
    }
    /* Write and read each connection asynchronously */
    ConnObjs_WriteRead(obj, cnt);


    /* Cleanup and return */
    WolfSSL_CleanupObjs(ctx, obj, cnt);
    WolfSSL_Cleanup(ctx, cnt);
    ConnCtx_Finish(connCtx);
    for (i = 0; i < cnt; i++)
        ConnObj_Free(&obj[i]);
    ConnCtx_Free(connCtx);
    free(obj);

    return 0;
}

