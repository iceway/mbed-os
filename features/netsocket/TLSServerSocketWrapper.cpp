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

#include "TLSServerSocketWrapper.h"
#include "platform/Callback.h"
#include "drivers/Timer.h"
#include "events/mbed_events.h"
#include <cstdint>
#include <cstdio>

#define TRACE_GROUP "TLSW"
#include "mbed-trace/mbed_trace.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"
#include "mbed_error.h"
#include "Kernel.h"

// This class requires Mbed TLS SSL/TLS server code
#if defined(MBEDTLS_SSL_SRV_C)

TLSServerSocketWrapper::TLSServerSocketWrapper(Socket *transport, const char *hostname, control_transport control) :
    _transport(transport),
    _timeout(-1),
#ifdef MBEDTLS_X509_CRT_PARSE_C
    _cacert(NULL),
    _srvcert(NULL),
#endif
    _ssl_conf(NULL),
    _connect_transport(control == TRANSPORT_CONNECT || control == TRANSPORT_CONNECT_AND_CLOSE),
    _close_transport(control == TRANSPORT_CLOSE || control == TRANSPORT_CONNECT_AND_CLOSE),
    _tls_initialized(false),
    _handshake_completed(false),
    _cacert_allocated(false),
    _srvcert_allocated(false),
    _ssl_conf_allocated(false)
{
#if defined(MBEDTLS_PLATFORM_C)
    int ret = mbedtls_platform_setup(NULL);
    if (ret != 0) {
        print_mbedtls_error("mbedtls_platform_setup()", ret);
    }
#endif /* MBEDTLS_PLATFORM_C */
    mbedtls_entropy_init(&_entropy);
    DRBG_INIT(&_drbg);

    mbedtls_ssl_init(&_ssl);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_pk_init(&_pkctx);
#endif
}

TLSServerSocketWrapper::~TLSServerSocketWrapper()
{
    if (_transport) {
        close();
    }
    mbedtls_entropy_free(&_entropy);

    DRBG_FREE(&_drbg);

    mbedtls_ssl_free(&_ssl);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_pk_free(&_pkctx);
    set_own_cert(NULL);
    set_ca_chain(NULL);
#endif
    set_ssl_config(NULL);
#if defined(MBEDTLS_PLATFORM_C)
    mbedtls_platform_teardown(NULL);
#endif /* MBEDTLS_PLATFORM_C */
}

nsapi_error_t TLSServerSocketWrapper::set_root_ca_cert(const void *root_ca, size_t len)
{
#if !defined(MBEDTLS_X509_CRT_PARSE_C)
    return NSAPI_ERROR_UNSUPPORTED;
#else
    mbedtls_x509_crt *crt;

    crt = new (std::nothrow) mbedtls_x509_crt;
    if (!crt) {
        return NSAPI_ERROR_NO_MEMORY;
    }

    mbedtls_x509_crt_init(crt);

    /* Parse CA certification */
    int ret;
    if ((ret = mbedtls_x509_crt_parse(crt, static_cast<const unsigned char *>(root_ca),
                                      len)) != 0) {
        print_mbedtls_error("mbedtls_x509_crt_parse", ret);
        mbedtls_x509_crt_free(crt);
        delete crt;
        return NSAPI_ERROR_PARAMETER;
    }
    set_ca_chain(crt);
    _cacert_allocated = true;
    return NSAPI_ERROR_OK;
#endif
}

nsapi_error_t TLSServerSocketWrapper::set_root_ca_cert(const char *root_ca_pem)
{
    return set_root_ca_cert(root_ca_pem, strlen(root_ca_pem) + 1);
}

nsapi_error_t TLSServerSocketWrapper::set_server_cert_key(const char *server_cert_pem, const char *server_private_key_pem)
{
    return set_server_cert_key(server_cert_pem, strlen(server_cert_pem) + 1, server_private_key_pem, strlen(server_private_key_pem) + 1);
}

nsapi_error_t TLSServerSocketWrapper::set_server_cert_key(const void *server_cert, size_t server_cert_len,
                                                    const void *server_private_key_pem, size_t server_private_key_len)
{
#if !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_PK_C)
    return NSAPI_ERROR_UNSUPPORTED;
#else

    int ret;
    mbedtls_x509_crt *crt = new mbedtls_x509_crt;
    mbedtls_x509_crt_init(crt);
    if ((ret = mbedtls_x509_crt_parse(crt, static_cast<const unsigned char *>(server_cert),
                                      server_cert_len)) != 0) {
        print_mbedtls_error("mbedtls_x509_crt_parse", ret);
        mbedtls_x509_crt_free(crt);
        delete crt;
        return NSAPI_ERROR_PARAMETER;
    }
    mbedtls_pk_init(&_pkctx);
    if ((ret = mbedtls_pk_parse_key(&_pkctx, static_cast<const unsigned char *>(server_private_key_pem),
                                    server_private_key_len, NULL, 0)) != 0) {
        print_mbedtls_error("mbedtls_pk_parse_key", ret);
        mbedtls_x509_crt_free(crt);
        delete crt;
        return NSAPI_ERROR_PARAMETER;
    }
    set_own_cert(crt);
    _srvcert_allocated = true;

    return NSAPI_ERROR_OK;
#endif /* MBEDTLS_X509_CRT_PARSE_C */
}

nsapi_error_t TLSServerSocketWrapper::do_handshake(bool first_call)
{
    return start_handshake(first_call);
}

nsapi_error_t TLSServerSocketWrapper::start_handshake(bool first_call)
{
    const char DRBG_PERS[] = "mbed TLS server";
    int ret;

    if (!_transport) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    if (_tls_initialized) {
        return continue_handshake();
    }

    tr_info("Starting TLS handshake");

    /*
     * Initialize TLS-related stuf.
     */
#if defined(MBEDTLS_CTR_DRBG_C)
    if ((ret = mbedtls_ctr_drbg_seed(&_drbg, mbedtls_entropy_func, &_entropy,
                                     (const unsigned char *) DRBG_PERS,
                                     sizeof(DRBG_PERS))) != 0) {
        print_mbedtls_error("mbedtls_crt_drbg_init", ret);
        return NSAPI_ERROR_AUTH_FAILURE;
    }
#elif defined(MBEDTLS_HMAC_DRBG_C)
    if ((ret = mbedtls_hmac_drbg_seed(&_drbg, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                                      mbedtls_entropy_func, &_entropy,
                                      (const unsigned char *) DRBG_PERS,
                                      sizeof(DRBG_PERS))) != 0) {
        print_mbedtls_error("mbedtls_hmac_drbg_seed", ret);
        return NSAPI_ERROR_AUTH_FAILURE;
    }
#else
#error "CTR or HMAC must be defined for TLSServerSocketWrapper!"
#endif

#if !defined(MBEDTLS_SSL_CONF_RNG)
    mbedtls_ssl_conf_rng(get_ssl_config(), DRBG_RANDOM, &_drbg);
#endif


#if MBED_CONF_TLS_SOCKET_DEBUG_LEVEL > 0
    mbedtls_ssl_conf_verify(get_ssl_config(), my_verify, NULL);
    mbedtls_ssl_conf_dbg(get_ssl_config(), my_debug, NULL);
    mbedtls_debug_set_threshold(MBED_CONF_TLS_SOCKET_DEBUG_LEVEL);
#endif

    tr_debug("mbedtls_ssl_setup()");
    if ((ret = mbedtls_ssl_setup(&_ssl, get_ssl_config())) != 0) {
        print_mbedtls_error("mbedtls_ssl_setup", ret);
        return NSAPI_ERROR_AUTH_FAILURE;
    }

    _transport->set_blocking(false);
    _transport->sigio(mbed::callback(this, &TLSServerSocketWrapper::event));

    // Defines MBEDTLS_SSL_CONF_RECV/SEND/RECV_TIMEOUT define global functions which should be the same for all
    // callers of mbedtls_ssl_set_bio_ctx and there should be only one ssl context. If these rules don't apply,
    // these defines can't be used.
#if !defined(MBEDTLS_SSL_CONF_RECV) && !defined(MBEDTLS_SSL_CONF_SEND) && !defined(MBEDTLS_SSL_CONF_RECV_TIMEOUT)
    mbedtls_ssl_set_bio(&_ssl, this, ssl_send, ssl_recv, nullptr);
#else
    mbedtls_ssl_set_bio_ctx(&_ssl, this);
#endif /* !defined(MBEDTLS_SSL_CONF_RECV) && !defined(MBEDTLS_SSL_CONF_SEND) && !defined(MBEDTLS_SSL_CONF_RECV_TIMEOUT) */

    _tls_initialized = true;

    ret = continue_handshake();
    if (first_call) {
        if (ret == NSAPI_ERROR_ALREADY) {
            ret = NSAPI_ERROR_IN_PROGRESS; // If first call should return IN_PROGRESS
        }
        if (ret == NSAPI_ERROR_IS_CONNECTED) {
            ret = NSAPI_ERROR_OK;   // If we happened to complete the request on the first call, return OK.
        }
    }
    return ret;
}

nsapi_error_t TLSServerSocketWrapper::continue_handshake()
{
    int ret;

    if (_handshake_completed) {
        return NSAPI_ERROR_IS_CONNECTED;
    }

    if (!_tls_initialized) {
        return NSAPI_ERROR_NO_CONNECTION;
    }

    while (true) {
        ret = mbedtls_ssl_handshake(&_ssl);
        if (_timeout && (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
            uint32_t flag;
            flag = _event_flag.wait_any(1, _timeout);
            if (flag & osFlagsError) {
                break;
            }
        } else {
            break;
        }
    }

    if (ret < 0) {
        print_mbedtls_error("mbedtls_ssl_handshake", ret);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return NSAPI_ERROR_ALREADY;
        } else {
            return NSAPI_ERROR_AUTH_FAILURE;
        }
    }

    tr_info("TLS connection established");

    _handshake_completed = true;
    return NSAPI_ERROR_IS_CONNECTED;
}


nsapi_error_t TLSServerSocketWrapper::send(const void *data, nsapi_size_t size)
{
    int ret;

    if (!_transport) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    tr_debug("send %d", size);
    while (true) {
        if (!_handshake_completed) {
            ret = continue_handshake();
            if (ret != NSAPI_ERROR_IS_CONNECTED) {
                if (ret == NSAPI_ERROR_ALREADY) {
                    ret = NSAPI_ERROR_WOULD_BLOCK;
                }
                return ret;
            }
        }

        ret = mbedtls_ssl_write(&_ssl, (const unsigned char *) data, size);

        if (_timeout == 0) {
            break;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_WANT_READ) {
            uint32_t flag;
            flag = _event_flag.wait_any(1, _timeout);
            if (flag & osFlagsError) {
                // Timeout break
                break;
            }
        } else {
            break;
        }
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
            ret == MBEDTLS_ERR_SSL_WANT_READ) {
        // translate to socket error
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    if (ret < 0) {
        print_mbedtls_error("mbedtls_ssl_write", ret);
        return NSAPI_ERROR_DEVICE_ERROR;
    }
    return ret; // Assume "non negative errorcode" to be propagated from Socket layer
}

nsapi_size_or_error_t TLSServerSocketWrapper::sendto(const SocketAddress &, const void *data, nsapi_size_t size)
{
    // Ignore the SocketAddress
    return send(data, size);
}

nsapi_size_or_error_t TLSServerSocketWrapper::recv(void *data, nsapi_size_t size)
{
    int ret;

    if (!_transport) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    while (true) {
        if (!_handshake_completed) {
            ret = continue_handshake();
            if (ret != NSAPI_ERROR_IS_CONNECTED) {
                if (ret == NSAPI_ERROR_ALREADY) {
                    ret = NSAPI_ERROR_WOULD_BLOCK;
                }
                return ret;
            }
        }

        ret = mbedtls_ssl_read(&_ssl, (unsigned char *) data, size);

        if (_timeout == 0) {
            break;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_WANT_READ) {
            uint32_t flag;
            flag = _event_flag.wait_any(1, _timeout);
            if (flag & osFlagsError) {
                // Timeout break
                break;
            }
        } else {
            break;
        }
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
            ret == MBEDTLS_ERR_SSL_WANT_READ) {
        // translate to socket error
        return NSAPI_ERROR_WOULD_BLOCK;
    } else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        /* MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY is not considered as error.
         * Just ignore here. Once connection is closed, mbedtls_ssl_read()
         * will return 0.
         */
        return 0;
    } else if (ret < 0) {
        print_mbedtls_error("mbedtls_ssl_read", ret);
        // There is no mapping of TLS error codes to Socket API so return most generic error to application
        return NSAPI_ERROR_DEVICE_ERROR;
    }
    return ret;
}

nsapi_size_or_error_t TLSServerSocketWrapper::recvfrom(SocketAddress *address, void *data, nsapi_size_t size)
{
    if (address) {
        getpeername(address);
    }
    return recv(data, size);
}

void TLSServerSocketWrapper::print_mbedtls_error(MBED_UNUSED const char *name, MBED_UNUSED int err)
{
// Avoid pulling in mbedtls_strerror when trace is not enabled
#if defined FEA_TRACE_SUPPORT && defined MBEDTLS_ERROR_C
    char *buf = new char[128];
    mbedtls_strerror(err, buf, 128);
    tr_err("%s() failed: -0x%04x (%d): %s", name, -err, err, buf);
    delete[] buf;
#else
    tr_err("%s() failed: -0x%04x (%d)", name, -err, err);
#endif
}


#if MBED_CONF_TLS_SOCKET_DEBUG_LEVEL > 0

void TLSServerSocketWrapper::my_debug(void *ctx, int level, const char *file, int line,
                                const char *str)
{
    const char *p, *basename;
    (void) ctx;

    /* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }

    tr_debug("%s:%04d: |%d| %s", basename, line, level, str);
}


int TLSServerSocketWrapper::my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    const uint32_t buf_size = 1024;
    char *buf = new char[buf_size];
    (void) data;

    tr_debug("\nVerifying certificate at depth %d:\n", depth);
    mbedtls_x509_crt_info(buf, buf_size - 1, "  ", crt);
    tr_debug("%s", buf);

    if (*flags == 0) {
        tr_info("No verification issue for this certificate\n");
    } else {
        mbedtls_x509_crt_verify_info(buf, buf_size, "  ! ", *flags);
        tr_info("%s\n", buf);
    }

    delete[] buf;

    return 0;
}

#endif /* MBED_CONF_TLS_SOCKET_DEBUG_LEVEL > 0 */


int TLSServerSocketWrapper::ssl_recv(void *ctx, unsigned char *buf, size_t len)
{
    int recv;

    TLSServerSocketWrapper *my = static_cast<TLSServerSocketWrapper *>(ctx);

    if (!my->_transport) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    recv = my->_transport->recv(buf, len);

    if (NSAPI_ERROR_WOULD_BLOCK == recv) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    } else if (recv < 0) {
        tr_error("Socket recv error %d", recv);
    }
    // Propagate also Socket errors to SSL, it allows negative error codes to be returned here.
    return recv;
}

int TLSServerSocketWrapper::ssl_send(void *ctx, const unsigned char *buf, size_t len)
{
    int size = -1;
    TLSServerSocketWrapper *my = static_cast<TLSServerSocketWrapper *>(ctx);

    if (!my->_transport) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    size = my->_transport->send(buf, len);

    if (NSAPI_ERROR_WOULD_BLOCK == size) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    } else if (size < 0) {
        tr_error("Socket send error %d", size);
    }
    // Propagate also Socket errors to SSL, it allows negative error codes to be returned here.
    return size;
}

#if defined(MBEDTLS_X509_CRT_PARSE_C)

mbedtls_x509_crt *TLSServerSocketWrapper::get_own_cert()
{
    return _srvcert;
}

int TLSServerSocketWrapper::set_own_cert(mbedtls_x509_crt *crt)
{
    int ret = 0;
    if (_srvcert && _srvcert_allocated) {
        mbedtls_x509_crt_free(_srvcert);
        delete _srvcert;
        _srvcert_allocated = false;
    }
    _srvcert = crt;
    if (crt) {
        if ((ret = mbedtls_ssl_conf_own_cert(get_ssl_config(), _srvcert, &_pkctx)) != 0) {
            print_mbedtls_error("mbedtls_ssl_conf_own_cert", ret);
        }
    }
    return ret;
}

mbedtls_x509_crt *TLSServerSocketWrapper::get_ca_chain()
{
    return _cacert;
}

void TLSServerSocketWrapper::set_ca_chain(mbedtls_x509_crt *crt)
{
    if (_cacert && _cacert_allocated) {
        mbedtls_x509_crt_free(_cacert);
        delete _cacert;
        _cacert_allocated = false;
    }
    _cacert = crt;
    tr_debug("mbedtls_ssl_conf_ca_chain()");
    mbedtls_ssl_conf_ca_chain(get_ssl_config(), _cacert, NULL);
}

#endif /* MBEDTLS_X509_CRT_PARSE_C */

mbedtls_ssl_config *TLSServerSocketWrapper::get_ssl_config()
{
    if (!_ssl_conf) {
        int ret;
        _ssl_conf = new mbedtls_ssl_config;
        mbedtls_ssl_config_init(_ssl_conf);
        _ssl_conf_allocated = true;

        if ((ret = mbedtls_ssl_config_defaults(_ssl_conf,
                                               MBEDTLS_SSL_IS_SERVER,
                                               MBEDTLS_SSL_TRANSPORT_STREAM,
                                               MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
            set_ssl_config(NULL);
            MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_NETWORK_STACK, MBED_ERROR_CODE_OUT_OF_MEMORY), "mbedtls_ssl_config_defaults() failed");
            return NULL;
        }
        /* It is possible to disable authentication by passing
         * MBEDTLS_SSL_VERIFY_NONE in the call to mbedtls_ssl_conf_authmode()
         */
        mbedtls_ssl_conf_authmode(get_ssl_config(), MBEDTLS_SSL_VERIFY_NONE);
    }
    return _ssl_conf;
}

void TLSServerSocketWrapper::set_ssl_config(mbedtls_ssl_config *conf)
{
    if (_ssl_conf && _ssl_conf_allocated) {
        mbedtls_ssl_config_free(_ssl_conf);
        delete _ssl_conf;
        _ssl_conf_allocated = false;
    }
    _ssl_conf = conf;
}

mbedtls_ssl_context *TLSServerSocketWrapper::get_ssl_context()
{
    return &_ssl;
}

const char *TLSServerSocketWrapper::get_ssl_ciphersuite_and_version()
{
    static char info[256];
    char version[32] = {0};
    char cipher[224] = {0};

    memset(info, 0, sizeof(info));
    snprintf(version, sizeof(version) - 1, "Version: %s", mbedtls_ssl_get_version(get_ssl_context()));
    snprintf(cipher, sizeof(cipher) - 1, "CipherSuite: %s", mbedtls_ssl_get_ciphersuite(get_ssl_context()));
    snprintf(info, sizeof(info) - 1, "%s, %s", version, cipher);

    return info;
}

const char *TLSServerSocketWrapper::get_peer_info()
{
    static char info[256];
    SocketAddress addr;

    int rc = _transport->getpeername(&addr);
    snprintf(info, sizeof(info) - 1, "IP: %s, Port: %u", addr.get_ip_address(), (uint32_t)addr.get_port());

    return info;
}

nsapi_error_t TLSServerSocketWrapper::close()
{
    if (!_transport) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    tr_info("Closing TLS");

    int ret = 0;
    if (_handshake_completed) {
        _transport->set_blocking(true);
        ret = mbedtls_ssl_close_notify(&_ssl);
        if (ret) {
            print_mbedtls_error("mbedtls_ssl_close_notify", ret);
        }
        _handshake_completed = false;
    }

    if (_close_transport) {
        int ret2 = _transport->close();
        if (!ret) {
            ret = ret2;
        }
    }

    _transport = NULL;

    return ret;
}

nsapi_error_t TLSServerSocketWrapper::connect(const SocketAddress &address)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

nsapi_error_t TLSServerSocketWrapper::bind(const SocketAddress &address)
{
    if (!_transport) {
        return NSAPI_ERROR_NO_SOCKET;
    }
    return _transport->bind(address);
}

void TLSServerSocketWrapper::set_blocking(bool blocking)
{
    set_timeout(blocking ? -1 : 0);
}

void TLSServerSocketWrapper::set_timeout(int timeout)
{
    _timeout = timeout;
    if (!is_handshake_started() && timeout != -1 && _connect_transport) {
        // If we have not yet connected the transport, we need to modify its blocking mode as well.
        // After connection is initiated, it is already set to non blocking mode
        _transport->set_timeout(timeout);
    }
}

void TLSServerSocketWrapper::sigio(mbed::Callback<void()> func)
{
    if (!_transport) {
        return;
    }
    _sigio = func;
    _transport->sigio(mbed::callback(this, &TLSServerSocketWrapper::event));
}

nsapi_error_t TLSServerSocketWrapper::setsockopt(int level, int optname, const void *optval, unsigned optlen)
{
    if (!_transport) {
        return NSAPI_ERROR_NO_SOCKET;
    }
    return _transport->setsockopt(level, optname, optval, optlen);
}

nsapi_error_t TLSServerSocketWrapper::getsockopt(int level, int optname, void *optval, unsigned *optlen)
{
    if (!_transport) {
        return NSAPI_ERROR_NO_SOCKET;
    }
    return _transport->getsockopt(level, optname, optval, optlen);
}

Socket *TLSServerSocketWrapper::accept(nsapi_error_t *err)
{
    if (err) {
        *err = NSAPI_ERROR_UNSUPPORTED;
    }
    return NULL;
}

nsapi_error_t TLSServerSocketWrapper::listen(int backlog)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

void TLSServerSocketWrapper::event()
{
    _event_flag.set(1);
    if (_sigio) {
        _sigio();
    }
}

bool TLSServerSocketWrapper::is_handshake_started() const
{
    return _tls_initialized;
}


nsapi_error_t TLSServerSocketWrapper::getpeername(SocketAddress *address)
{
    if (!_handshake_completed) {
        return NSAPI_ERROR_NO_CONNECTION;
    }
    return _transport->getpeername(address);
}

#endif /* MBEDTLS_SSL_SRV_C */
