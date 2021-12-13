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

#include "TLSServerSocket.h"

#define TRACE_GROUP "TLSS"
#include "mbed-trace/mbed_trace.h"

#if !defined(MBED_CONF_NSAPI_OFFLOAD_TLSSOCKET) || !(MBED_CONF_NSAPI_OFFLOAD_TLSSOCKET)

// This class requires Mbed TLS SSL/TLS server code
#if defined(MBEDTLS_SSL_SRV_C)
TLSServerSocket::~TLSServerSocket()
{
    /* Transport is a member of TLSServerSocket which is derived from TLSSocketWrapper.
     * Make sure that TLSSocketWrapper::close() is called before the transport is
     * destroyed.
     */
    close();
    if (_tcp_socket) {
        _tcp_socket = NULL;
    }
}
#endif // MBEDTLS_SSL_SRV_C

#else // MBED_CONF_NSAPI_OFFLOAD_TLSSOCKET

TLSServerSocket::TLSServerSocket()
{
}

TLSServerSocket::~TLSServerSocket()
{
}


nsapi_error_t TLSServerSocket::set_hostname(const char *hostname)
{
    return setsockopt(NSAPI_TLSSOCKET_LEVEL, NSAPI_TLSSOCKET_SET_HOSTNAME, hostname, strlen(hostname));
}

nsapi_error_t TLSServerSocket::set_root_ca_cert(const void *root_ca, size_t len)
{
    return setsockopt(NSAPI_TLSSOCKET_LEVEL, NSAPI_TLSSOCKET_SET_CACERT, root_ca, len);
}

nsapi_error_t TLSServerSocket::set_root_ca_cert(const char *root_ca_pem)
{
    return set_root_ca_cert(root_ca_pem, strlen(root_ca_pem));
}

nsapi_error_t TLSServerSocket::set_server_cert_key(const void *server_cert, size_t server_cert_len,
                                             const void *server_private_key_pem, size_t server_private_key_len)
{
    nsapi_error_t ret = setsockopt(NSAPI_TLSSOCKET_LEVEL, NSAPI_TLSSOCKET_SET_CLCERT, server_cert, server_cert_len);
    if (ret == NSAPI_ERROR_OK) {
        ret = setsockopt(NSAPI_TLSSOCKET_LEVEL, NSAPI_TLSSOCKET_SET_CLKEY, server_private_key_pem, server_private_key_len);
    }
    return ret;
}

nsapi_error_t TLSServerSocket::set_server_cert_key(const char *server_cert_pem, const char *server_private_key_pem)
{
    return set_server_cert_key(server_cert_pem, strlen(server_cert_pem), server_private_key_pem, strlen(server_private_key_pem));
}

nsapi_error_t TLSServerSocket::connect(const char *host, uint16_t port)
{
    nsapi_error_t ret = enable_tlssocket();
    if (ret == NSAPI_ERROR_OK) {
        ret = TCPSocket::connect(host, port);
    }
    return ret;
}

nsapi_error_t TLSServerSocket::connect(const SocketAddress &address)
{
    nsapi_error_t ret = enable_tlssocket();
    if (ret == NSAPI_ERROR_OK) {
        ret = TCPSocket::connect(address);
    }
    return ret;
}

nsapi_error_t TLSServerSocket::enable_tlssocket()
{
    bool enabled = true;
    return setsockopt(NSAPI_TLSSOCKET_LEVEL, NSAPI_TLSSOCKET_ENABLE, &enabled, sizeof(enabled));
}

#endif // MBED_CONF_NSAPI_OFFLOAD_TLSSOCKET
