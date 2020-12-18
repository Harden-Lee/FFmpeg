//
//  ffmpeg-ws.h
//  websocket
//
//  Created by Harden.L on 2020/7/16.
//  Copyright © 2020 Harden.L. All rights reserved.
//

#ifndef ffmpeg_ws_h
#define ffmpeg_ws_h

#ifdef    __cplusplus
extern "C"
{
#endif

#include "js_util.h"

#ifndef __WIN32__
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
#endif
#include <time.h>

#define _free(p) do{free(p);p=NULL;}while(0)
    
typedef struct
{
    char scheme[8];
    char path[1024];
    char query[1024];
    char hostname[128];
    unsigned int port;
    
    char *uid;
    char *gid;

    char *ssl_key;
    char *ssl_crt;
    int ssl_no_verify;
} url_t;


typedef enum JSh264FrameType{
    eFrameTypeIFrame = 0x00,
    eFrameTypePFrame = 0x01,
    eFrameTypeBFrame = 0x02,
    eFrameTypeVideo = 0x03,
    eFrameTypeCustomProtocol = 0x04,
    eFrameTypeStatistic = 0x05,
    eFrameTypeAudio = 0x06
}JSh264FrameType;

typedef struct
{
    int fd;
//    char *recv_buff;
//    char *cont_data;
//    int32_t cont_data_size;
    void *ssl_ctx;

} wsContext_t;

void *ws_ssl_handshake(wsContext_t *, char *, char *, char *, int);
int ws_ssl_write(void *, uint8_t *, uint64_t);
int32_t ws_ssl_read(void *, uint8_t *, uint64_t);
void ws_ssl_close(void *);

#ifdef    __cplusplus
}
#endif
#endif /* ffmpeg_ws_h */
