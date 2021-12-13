/** @file TLSServerSocket.h TLSServerSocket */
/*
 * Copyright (c) 2018 ARM Limited
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/** @addtogroup netsocket
* @{
*/

#ifndef _MBED_HTTPS_TLS_SERVER_TCP_SOCKET_H_
#define _MBED_HTTPS_TLS_SERVER_TCP_SOCKET_H_

#include "netsocket/TCPSocket.h"

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#if !defined(MBED_CONF_NSAPI_OFFLOAD_TLSServerSocket) || !(MBED_CONF_NSAPI_OFFLOAD_TLSServerSocket)

// This class requires Mbed TLS SSL/TLS server code
#if defined(MBEDTLS_SSL_SRV_C) || defined(DOXYGEN_ONLY)

#include "TLSServerSocketWrapper.h"

/**
 * \brief TLSServerSocket is a wrapper around TCPSocket for interacting with TLS servers.
 *
 * TLSServerSocket uses the TLSServerSocketWrapper with internal TCP socket.
 * This is a helper for creating commonly used TLS connections over TCP.
 *
 */
class TLSServerSocket : public TLSServerSocketWrapper {
public:
    /** Create an uninitialized socket.
     *
     *  Must call open to initialize the socket on a network stack.
     */
    TLSServerSocket(TCPSocket *tcp_socket) : TLSServerSocketWrapper(tcp_socket) {
        _tcp_socket = tcp_socket;
    }

    /** Destroy the TLSServerSocket and closes the transport.
     */
    virtual ~TLSServerSocket();

    /** Opens a socket.
     *
     *  Creates a network socket on the network stack of the given
     *  network interface.
     *
     *  @note TLSServerSocket cannot be reopened after closing. It should be destructed to
     *        clear internal TLS memory structures.
     *
     *  @param stack    Network stack as target for socket.
     *  @return         NSAPI_ERROR_OK on success. See @ref TCPSocket::open
     */
    virtual nsapi_error_t open(NetworkStack *stack)
    {
        return _tcp_socket->open(stack);
    }

    template <typename S>
    nsapi_error_t open(S *stack)
    {
        return open(nsapi_create_stack(stack));
    }

private:
    TCPSocket *_tcp_socket;
};
#endif // MBEDTLS_SSL_SRV_C

#else // MBED_CONF_NSAPI_OFFLOAD_TLSServerSocket

class TLSServerSocket : public TCPSocket {
public:
    TLSServerSocket();
    virtual ~TLSServerSocket();

    /** Set hostname.
     *
     * TLSServerSocket requires hostname used to verify the certificate.
     * If hostname is not given in constructor, this function must be used before
     * starting the TLS handshake.
     *
     * @param hostname     Hostname of the remote host, used for certificate checking.
     */
    nsapi_error_t set_hostname(const char *hostname);

    /** Sets the certification of Root CA.
     *
     * @note Must be called after open() before calling connect()
     *
     * @param root_ca Root CA Certificate in any Mbed TLS-supported format.
     * @param len     Length of certificate (including terminating 0 for PEM).
     * @return        NSAPI_ERROR_OK on success, negative error code on failure.
     */
    virtual nsapi_error_t set_root_ca_cert(const void *root_ca, size_t len);

    /** Sets the certification of Root CA.
     *
     * @note Must be called after open() before calling connect()
     *
     * @param root_ca_pem Root CA Certificate in PEM format.
     */
    virtual nsapi_error_t set_root_ca_cert(const char *root_ca_pem);


    /** Sets server certificate, and server private key.
     *
     * @param server_cert server certification in PEM or DER format.
     * @param server_cert_len Certificate size including the terminating null byte for PEM data.
     * @param server_private_key_pem server private key in PEM or DER format.
     * @param server_private_key_len Key size including the terminating null byte for PEM data
     * @return   NSAPI_ERROR_OK on success, negative error code on failure.
     */
    virtual nsapi_error_t set_server_cert_key(const void *server_cert, size_t server_cert_len,
                                              const void *server_private_key_pem, size_t server_private_key_len);

    /** Sets server certificate, and server private key.
     *
     * @param server_cert_pem server certification in PEM format.
     * @param server_private_key_pem server private key in PEM format.
     * @return   NSAPI_ERROR_OK on success, negative error code on failure.
     */
    virtual nsapi_error_t set_server_cert_key(const char *server_cert_pem, const char *server_private_key_pem);

    // From TCPSocket
    virtual nsapi_error_t connect(const char *host, uint16_t port);
    virtual nsapi_error_t connect(const SocketAddress &address);

protected:
    virtual nsapi_error_t enable_TLSServerSocket();
};

#endif // MBED_CONF_NSAPI_OFFLOAD_TLSServerSocket

#endif // _MBED_HTTPS_TLS_SERVER_TCP_SOCKET_H_

/** @} */
