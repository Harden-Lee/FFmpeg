//
//  jsh264socket.h
//  IJKMediaFramework
//
//  Created by Zaki on 2020/1/13.
//  Copyright © 2020 bilibili. All rights reserved.
//

#ifndef jsh264socket_h
#define jsh264socket_h

#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include "libavutil/application.h"
#include "libavformat/avformat.h"x
#include "libavformat/url.h"
#include "libavutil/avstring.h"
#include "libavutil/log.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "libavutil/common.h"
#include "js_websocket.h"
#include "jsh264.h"
#include "string.h"
#include "comm.pb-c.h"
#include "player.pb-c.h"

#define kMaxReadSize 1024*1024

typedef struct PC_HEADER{
    uint32_t code;
    uint16_t cmd;
}PC_HEAD;

typedef struct JSContext {
    AVClass        *class;
    URLContext     *inner;
    wsContext_t    *socket_ctx;
    
    
    uint8_t        *cache_data;
    int             cache_data_size;
    int64_t         cache_data_max_size;
    
    int             find_stream;

    // 第一次获取到的时间戳
    int64_t         base_time;
    // 上一次接受数据时间戳
    int64_t         last_time;

    /* options */
    char           *url;
    char           *n_url;
} JSContext;

// 发送心跳
static int jsh264_socket_heart_msg(URLContext *h)
{
    av_log(NULL, AV_LOG_ERROR,"jsh264_socket_heart_msg\n");
    JSContext *c = h->priv_data;
    if (!c || !c->socket_ctx)
    {
        return AVERROR(EIO);
    }

    Livepb__Comm__CsCommHeartbeatReq *mReq = av_mallocz(sizeof(Livepb__Comm__CsCommHeartbeatReq));
    livepb__comm__cs_comm_heartbeat_req__init(mReq);

    uint8_t *protobuf_data = av_mallocz(1024*50);
    size_t protobuf_data_size = livepb__comm__cs_comm_heartbeat_req__pack(mReq, protobuf_data);
    assert(protobuf_data_size);
    // printf("protobuf data get size %d\n", protobuf_data_size);

    // 消息头数据
    int total_size = (int)protobuf_data_size + 6;
    char header[6];
    header[0] = 0x04;
    header[1] = total_size >> 16 & 0xFF;
    header[2] = total_size >> 8 & 0xFF;
    header[3] = total_size & 0xFF;
    // uint16_t msg_id = 10000;
    // msg_id = htons(msg_id);
    // memcpy(header + 4,&msg_id,2);
    header[4] = 10000 >> 8 & 0xFF; // 10000 心跳连接
    header[5] = 10000 & 0xFF;

    // 合并header、protobuf数据
    uint8_t *sendData = av_mallocz(total_size);
    memcpy(sendData, header, 6);
    memcpy(sendData+6, protobuf_data, protobuf_data_size);
    /*----------------心跳信令----------------*/
    
    // 发送
    sendBinary(c->socket_ctx, sendData, total_size);
    free(mReq);
    free(protobuf_data);
    free(sendData);
    av_log(NULL, AV_LOG_ERROR,"jsh264_socket_heart_msg --- \n");
    return 0;
}

static void SignalHandler(int signal)
{
     av_log(NULL, AV_LOG_ERROR,"Application aborting...signal == %d\n",signal);
}


static int jsh264_open(URLContext *h, const char *arg, int flags, AVDictionary **options)
{
    av_log(NULL, AV_LOG_ERROR, "------------ jsh264scoket_open ------------ %s \n",arg);
    int32_t ret = 0;
    JSContext *c = h->priv_data;
    c->url = arg;

    if (!c)
        return AVERROR(ENXIO);
    
    
//    signal(SIGBUS, SignalHandler);
//    signal(SIGSEGV,SignalHandler);

    /**------字符串处理 分别得到url、token、streamId **/
    char *original = arg;
//wss://awswss.cddxsbkj.com:9090?token=0c19946d749d0bbf2cc87fcb310c8bb61602301538188zr_game_1001477599&streamId=b011
    
    if (original == NULL) {
        return AVERROR(ENOENT);
    }
    int arglen = strlen(original);
    if (arglen <= 0) {
        return AVERROR(ENOENT);
    }
    char *lastStr = strstr(original,"?");
    if (lastStr == NULL) {
        return AVERROR(ENOENT);
    }
    int endlen = strlen(lastStr);
    //url
    int url_length = arglen - endlen + 1;
    if (url_length <= 0) {
        return AVERROR(ENOENT);
    }
    char *url = (char*) malloc(url_length);
    memset(url, '\0', url_length);
    strncpy(url,original,url_length -1);

    //token
    char *streamStr = strstr(lastStr,"&");
    if (streamStr == NULL) {
        return AVERROR(ENOENT);
    }
    int streamlen = strlen(streamStr);
    int tokenlen = strlen("?token=");
    int token_length = endlen - streamlen - tokenlen + 1;
    if (token_length <= 0) {
        return AVERROR(ENOENT);
    }
    char *token = (char*) malloc(token_length);
    memset(token, '\0', token_length);
    strncpy(token,lastStr+tokenlen, token_length -1);
    
    //stream_id
    int streamidlen = strlen("&streamId=");
    int stream_length = streamlen - streamidlen + 1;
    if (stream_length <= 0) {
        return AVERROR(ENOENT);
    }
    char *stream_id = (char*) malloc(stream_length);
    memset(stream_id, '\0', stream_length);
    strncpy(stream_id,streamStr+streamidlen,stream_length-1);

//    char *newstr = strReplace(url, substr, replace);
//    char *newstr = "wss://szdx.cddxsbkj.com:9090";
//    char *newstr = "ws://47.90.38.60:9010"
    
    av_log(NULL, AV_LOG_ERROR,"url = %s token = %s stream_id = %s\n", url,token,stream_id);

    c->n_url = url;

    av_log(NULL, AV_LOG_ERROR,"start socket connect\n");
    wsContext_t *ctx = NULL;
    ctx = wsContextNew();
    ret = wsCreateConnection(ctx, url);
    if (ret <= 0){
        av_log(NULL, AV_LOG_ERROR,"socket 连接错误\n");
        free(url);
        free(token);
        free(stream_id);
        return AVERROR(ENOENT);
    }
    av_log(NULL, AV_LOG_ERROR,"socket connected\n");
    // 添加到上下文
    c->socket_ctx = ctx;
    c->cache_data = av_mallocz(kMaxReadSize);
    c->cache_data_max_size = kMaxReadSize;
    c->cache_data_size = 0;
    // 第一次打开链接时间戳
    c->base_time = av_gettime();
    c->last_time = c->base_time;

    /*----------------socket连接----------------*/


    /*----------------登录信令----------------*/
    Livepb__Comm__CsCommLoginReq *mReq = av_mallocz(sizeof(Livepb__Comm__CsCommLoginReq));
    livepb__comm__cs_comm_login_req__init(mReq);
    mReq->stream_id = stream_id;//9527
    mReq->app = "live";
    mReq->login_type = LIVEPB__COMM__LOGIN_TYPE__ByToken;
    mReq->token = token;

    uint8_t *protobuf_data = av_mallocz(1024*50);
    size_t protobuf_data_size = livepb__comm__cs_comm_login_req__pack(mReq, protobuf_data);
    assert(protobuf_data_size);
    av_log(NULL, AV_LOG_ERROR,"protobuf data get size %d\n", protobuf_data_size);
    
    // 消息头数据
    int total_size = (int)protobuf_data_size + 6;
    char header[6];
    header[0] = 0x04;
    header[1] = total_size >> 16 & 0xFF;
    header[2] = total_size >> 8 & 0xFF;
    header[3] = total_size & 0xFF;
    header[4] = 10002 >> 8 & 0xFF; // 10002 登录消息
    header[5] = 10002 & 0xFF;

    // 合并header、protobuf数据
    uint8_t *sendData = av_mallocz(total_size);
    memcpy(sendData, header, 6);
    memcpy(sendData+6, protobuf_data, protobuf_data_size);
    /*----------------登录信令----------------*/
    
    // 发送登录
    sendBinary(ctx, sendData, total_size);

    // 读取socket数据
    uint8_t *response_data = (uint8_t *)av_mallocz(kMaxReadSize);
    uint8_t len = recvData(c->socket_ctx, response_data, kMaxReadSize);
    av_log(NULL, AV_LOG_ERROR,"read_header_len: %d\n", len);
    free(response_data);

    // 释放内存
    free(url);
    free(token);
    free(stream_id);
    free(sendData);
    free(mReq);
    free(protobuf_data);
    
    av_log(NULL, AV_LOG_ERROR,"------------ jsh264scoket_open  end ------------ \n");
    return ret > 0 ? 0 : ret;
    
}


static int jsh264_close(URLContext *h)
{
    av_log(NULL, AV_LOG_ERROR,"jsh264scoket_close \n");
    
    JSContext *c = h->priv_data;

    wsContextFree(c->socket_ctx);
    c->socket_ctx = NULL;
    
    free(c->cache_data);
    
    c->base_time = 0;
    c->last_time = 0;
    
    return 0;
    // return ffurl_close(c->inner);
}

static int jsh264_read(URLContext *h, unsigned char *buf, int size)
{
    JSContext *c = h->priv_data;
    if (c == NULL || c->socket_ctx == NULL || c->cache_data == NULL){
        av_log(NULL, AV_LOG_ERROR,"c->socket_ctx == NULL\n");
        return 0;
    }
    //读取到实际数据总长度
    int read_len = 0;
    if (c->cache_data_size) {
        av_log(NULL, AV_LOG_ERROR,"read cache_data_size start\n");
        read_len = FFMIN(size,c->cache_data_size);
        memcpy(buf, c->cache_data, read_len);
        if (c->cache_data_size > size) {
            int cache_data_size = c->cache_data_size - read_len;
            uint8_t *cache_data = (uint8_t *)av_mallocz(cache_data_size);
            if (cache_data == NULL) {
                return AVERROR(ENOMEM);
            }
            memcpy(cache_data, c->cache_data + read_len, cache_data_size);
            
            memset(c->cache_data,0,kMaxReadSize);
            memcpy(c->cache_data, cache_data, cache_data_size);
            c->cache_data_size = cache_data_size;
            free(cache_data);
        }
        else
        {
            memset(c->cache_data,0,kMaxReadSize);
            c->cache_data_size = 0;
        }
        return read_len;
    }
    
    av_log(NULL, AV_LOG_ERROR,"socket read 数据 start\n");
    // 读取数据
    uint8_t *response_data = NULL;
    response_data = (uint8_t *)av_mallocz(kMaxReadSize);
    if (response_data == NULL)
        return AVERROR(ENOMEM);
    memset(response_data,0,kMaxReadSize);
    // 读取socket数据
    int len = recvData(c->socket_ctx, response_data, kMaxReadSize);
    av_log(NULL, AV_LOG_ERROR,"real read len == %d\n",len);
    if (len < 0){
        av_log(NULL, AV_LOG_ERROR,"real read AVERROR\n");
        free(response_data);
        return AVERROR(EIO);
    }
    
    read_len = FFMIN(size,len);
    // 填充到io
    memcpy(buf, response_data, read_len);
    
    if (len > size) {
        c->cache_data_size = FFMIN(len - read_len,c->cache_data_max_size);
        memcpy(c->cache_data,response_data+read_len,c->cache_data_size);
    }
    
    //解析业务数据
    uint8_t *header_data = NULL;
    header_data = (uint8_t *)av_mallocz(read_len);
    if (header_data == NULL)
        return AVERROR(ENOMEM);
    memset(header_data,0,read_len);
    memcpy(header_data, response_data, read_len);
    const PC_HEAD * header = (const PC_HEAD *)header_data;
    
    int header_must = ntohl(header->code);
    // 获取帧类型
    JSh264FrameType frame_type = header_must >> 24 & 0xFF;
    av_log(NULL, AV_LOG_ERROR,"frame_type---->%ld \n", frame_type);
    // TODO: 两个业务数据帧的处理
    if (frame_type == eFrameTypeCustomProtocol || frame_type == eFrameTypeStatistic)
    {
        uint16_t custom_type = 0;
        custom_type = ntohs(header->cmd);
        av_log(NULL, AV_LOG_ERROR,"frame_type---->%ld  custom_type = %ld\n", frame_type,custom_type);
        if (custom_type == 10100 || custom_type == 10101 || custom_type == 10104) {
            free(header_data);
            free(response_data);
            header = NULL;
            return AVERROR(ENOENT);
        }
    }
    
    // 当前时间戳
    int64_t current_time = 0;
    current_time = av_gettime();
    // 比较上一次时间戳
    if (c->last_time && ((current_time - c->last_time)/ 1000) > 10000)
    {
        // 发送心跳信令
        av_log(NULL, AV_LOG_ERROR,"发送心跳\n");
        jsh264_socket_heart_msg(h);
        // 更新读取时间戳
        c->last_time = FFMAX(c->last_time, current_time);
    }
    
    av_log(NULL, AV_LOG_ERROR,"read end free buf\n");
    free(header_data);
    free(response_data);
    header = NULL;
    return read_len;
}

static int jsh264_write(URLContext *h, unsigned char *buf, int size)
{
    av_log(NULL, AV_LOG_ERROR,"jsh264_write \n");
    JSContext *c = h->priv_data;

    return 0;
    // return ffurl_read(c->inner, buf, size);
}

static int64_t jsh264_seek(URLContext *h, int64_t pos, int whence)
{
    av_log(NULL, AV_LOG_ERROR,"jsh264scoket_seek \n");
    JSContext *c = h->priv_data;

    return ffurl_seek(c->inner, pos, whence);
}

static const AVClass jsh264_class = {
    .class_name = "libjsh264_protocol",
    .item_name  = av_default_item_name,
    // .option     = options,
    .version    = LIBAVUTIL_VERSION_INT
};

const URLProtocol ff_ws_protocol = {
    .name = "ws",
    .url_open2           = jsh264_open,
    .url_read            = jsh264_read,
    .url_close           = jsh264_close,
    .url_write           = jsh264_write,
    .priv_data_size      = sizeof(JSContext),
    .priv_data_class     = &jsh264_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK
};

const URLProtocol ff_wss_protocol = {
    .name = "wss",
    .url_open2           = jsh264_open,
    .url_read            = jsh264_read,
    .url_close           = jsh264_close,
    .url_write           = jsh264_write,
    .priv_data_size      = sizeof(JSContext),
    .priv_data_class     = &jsh264_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK
};

#endif /* jsh264socket_h */
