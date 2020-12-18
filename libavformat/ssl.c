#include "ffmpeg-ws.h"

#ifndef __WIN32__

static int _ws_ssl_wait_read(fd) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(fd, &rset);
        if (select(fd+1, &rset, NULL, NULL, NULL) < 0) {
//                printf("_ws_ssl_wait_read()/select()");
                return -1;
        }
        return 0;
}

static int _ws_ssl_wait_write(fd) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        if (select(fd+1, NULL, &wset, NULL, NULL) < 0) {
//                printf("_ws_ssl_wait_write()/select()");
                return -1;
        }
        return 0;
}
#endif

#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <poll.h>
//#include <sys/epoll.h>

static int ssl_initialized = 0;
int ssl_peer_index = -1;
static SSL_CTX *ssl_ctx = NULL;

void *ws_ssl_handshake(wsContext_t *peer, char *sni, char *key, char *crt,int ssl_no_verify) {
    if (!ssl_initialized) {
        OPENSSL_config(NULL);
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ssl_initialized = 1;
    }
    
    if (!ssl_ctx) {
        ssl_ctx = SSL_CTX_new(SSLv23_method());
        if (!ssl_ctx) {
            av_log(NULL, AV_LOG_ERROR,"ws_ssl_handshake(): unable to initialize context\n");
            return NULL;
        }
        long ssloptions = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_ALL | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
#ifdef SSL_OP_NO_COMPRESSION
        ssloptions |= SSL_OP_NO_COMPRESSION;
#endif
        // release/reuse buffers as soon as possibile
#ifdef SSL_MODE_RELEASE_BUFFERS
        SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
        if (ssl_no_verify) {
            SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
        }
        else {
            SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        }
        ssl_peer_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        
        if (key) {
            if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key, SSL_FILETYPE_PEM) <= 0) {
                av_log(NULL, AV_LOG_ERROR,"ws_ssl_handshake(): unable to load key %s\n", key);
                SSL_CTX_free(ssl_ctx);
                ssl_ctx = NULL;
                return NULL;
            }
        }
        
        if (crt) {
            if (SSL_CTX_use_certificate_chain_file(ssl_ctx, crt) <= 0) {
                av_log(NULL, AV_LOG_ERROR,"ws_ssl_handshake(): unable to load certificate %s\n", crt);
                SSL_CTX_free(ssl_ctx);
                ssl_ctx = NULL;
                return NULL;
            }
        }
    }
    
    
    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        av_log(NULL, AV_LOG_ERROR,"ws_ssl_handshake(): unable to initialize session\n");
        return NULL;
    }
    SSL_set_fd(ssl, peer->fd);
    SSL_set_tlsext_host_name(ssl, sni);
    
    SSL_set_ex_data(ssl, ssl_peer_index, peer);
    int err = 0;
    //    for(;;) {
    //        int ret = SSL_connect(ssl);
    //        if (ret > 0) break;
    //        if (ERR_peek_error()) {
    //            err = SSL_get_error(ssl, ret);
    //        }
    //        if (err == SSL_ERROR_WANT_READ) {
    //            if (_ws_ssl_wait_read(peer->fd)) goto error;
    //            av_log(NULL, AV_LOG_ERROR,"SSL_ERROR_WANT_READ continue\n");
    //            continue;
    //        }
    //        if (err == SSL_ERROR_WANT_WRITE) {
    //            if (_ws_ssl_wait_write(peer->fd)) goto error;
    //            av_log(NULL, AV_LOG_ERROR,"SSL_ERROR_WANT_WRITE continue\n");
    //            continue;
    //        }
    //        goto error;
    //    }
    int r = 0,timeOut = 0;
    while ((r = SSL_connect(ssl)) != 1) {
        if(++timeOut > 1000)
        {
            goto error;
        }
        delayms(1);
    }
    
    return ssl;
    
error:
    
    err = (int)ERR_get_error_line_data(NULL, NULL, NULL, NULL);
    av_log(NULL, AV_LOG_ERROR,"ws_ssl_handshake(): %s\n", ERR_error_string(err, NULL));
    ERR_clear_error();
    SSL_free(ssl);
    return NULL;
}

int ws_ssl_write(void *ctx, uint8_t *buf, uint64_t len) {
    wsContext_t *peer = (wsContext_t *) SSL_get_ex_data((SSL *)ctx, ssl_peer_index);
    for(;;) {
        int ret = SSL_write((SSL *)ctx, buf, (int)len);
        if (ret > 0) break;
        int err = 0;
        if (ERR_peek_error()) {
            err = SSL_get_error((SSL *)ctx, ret);
        }
        if (err == SSL_ERROR_WANT_READ) {
            if (_ws_ssl_wait_read(peer->fd)) return -1;
            continue;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            if (_ws_ssl_wait_write(peer->fd)) return -1;
            continue;
        }
        return -1;
        }
    return 0;
}

int32_t ws_ssl_read(void *ctx, uint8_t *buf, uint64_t len) {
    wsContext_t *peer = (wsContext_t *) SSL_get_ex_data((SSL *)ctx, ssl_peer_index);
    ssize_t ret = -1;
    ret = (ssize_t)SSL_read((SSL *)ctx, buf, (int)len);
    if (ret <=  0) {
//        ssize_t err = SSL_get_error((SSL *)ctx, (int)ret);
//        av_log(NULL, AV_LOG_ERROR,"ws_ssl_read--- err -- %s\n",ERR_error_string(err,NULL));
//
//        if (err == SSL_ERROR_WANT_READ) {
//            if (_ws_ssl_wait_read(peer->fd)) {
//                return -1;
//            }
//        }
//        if (err == SSL_ERROR_WANT_WRITE) {
//            if (_ws_ssl_wait_write(peer->fd)) {
//                return -1;
//            }
//        }
        return -1;
    }
    av_log(NULL, AV_LOG_ERROR,"end-ret:----------%d--%d",ret,len);
    return ret;
}

void ws_ssl_close(void *ctx) {
    wsContext_t *peer = (wsContext_t *) SSL_get_ex_data((SSL *)ctx, ssl_peer_index);
    
    int ret = SSL_shutdown(peer->ssl_ctx);
    av_log(NULL, AV_LOG_ERROR,"shutdown---%d\n",ret);
    if (ret <= 0) {
        int err = 0;
        if (ERR_peek_error()) {
            err = SSL_get_error((SSL *)ctx, ret);
            av_log(NULL, AV_LOG_ERROR,"shutdown-err==%s\n",ERR_error_string(err,NULL));
        }
        shutdown(peer->fd,1);
        ret = SSL_shutdown(peer->ssl_ctx);
        av_log(NULL, AV_LOG_ERROR,"SSL_shutdown --- %d hah\n",ret);
    }
    ERR_clear_error();
    SSL_free(peer->ssl_ctx);
//    SSLMap.erase(peer->fd);
//    shutdown(peer->fd,2);
}

