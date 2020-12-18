//
//  jsh264socket.h
//  IJKMediaFramework
//
//  Created by Zaki on 2020/1/13.
//  Copyright © 2020 bilibili. All rights reserved.
//

#ifndef jsh264dec_h
#define jsh264dec_h

#include <stdio.h>
#include <assert.h>
#include <pthread.h>

#include "libavutil/avstring.h"
#include "libavutil/channel_layout.h"
#include "libavutil/dict.h"
#include "libavutil/opt.h"
#include "libavutil/intfloat.h"
#include "libavutil/mathematics.h"
#include "libavcodec/bytestream.h"
#include "libavcodec/mpeg4audio.h"
#include "avformat.h"
#include "internal.h"
#include "avio_internal.h"
#include "jsh264.h"
#include "js_websocket.h"

typedef struct JSh264decContext
{
    /* data */
    const AVClass *class;
    int  is_connect;
    // pthread_t async_buffer_thread;
    // AVPacketList *queue, *queue_end;

    int64_t v_first_time;
    int64_t a_first_time;

}JSh264decContext;

static int probe_count = 0;

static int js_h264_probe(AVProbeData *p)
{
    av_log(NULL, AV_LOG_ERROR,"AVFormatContext js_h264_probe ---------------------- start  %s\n", p->filename);
    if (p->filename != NULL && av_stristart(p->filename, "wss:", NULL))
    {
         av_log(NULL, AV_LOG_ERROR,"AVFormatContext js_h264_probe ---------------------- end  wss\n");
        /* code */
        return AVPROBE_SCORE_MAX;
    }

    if (p->filename != NULL && av_stristart(p->filename, "ws:", NULL))
    {
         av_log(NULL, AV_LOG_ERROR,"AVFormatContext js_h264_probe ---------------------- end  ws\n");
        /* code */
        return AVPROBE_SCORE_MAX;
    }
    char *tmpBuf = p->buf;
    if (p->buf_size > 5
        && tmpBuf[0] == 0x7b 
        && tmpBuf[1] == 0x22
        && tmpBuf[2] == 0x61
        && tmpBuf[3] == 0x63
        && tmpBuf[4] == 0x74) {
            return AVPROBE_SCORE_MAX;
        }
    av_log(NULL, AV_LOG_ERROR,"AVFormatContext js_h264_probe ---------------------- end \n");
    return 0;
}
//static FILE *s_pFile = NULL;
static int js_read_header(AVFormatContext *s)
{
    
    // int ret = 1;
    // JSh264decContext *context = s->priv_data;
    // uint8_t *tmpBuf = s->pb->buf_ptr;
    // printf("get buffer ---> %.2x %.2x %.2x %.2x %.2x\n", tmpBuf[0], tmpBuf[1], tmpBuf[2], tmpBuf[3], tmpBuf[4]);
    // return ret;
    // int offset = 19;
    // avio_seek(s->pb, offset, SEEK_CUR);

    // printf("ffmpeg::file_path::%s\n", s->file_path);
//    s_pFile = fopen(s->file_path, "wb+");
//    if (s_pFile == NULL)
//    {
//        printf("s_pFile is NULL\n");
//    }

    av_log(NULL, AV_LOG_ERROR,"js_read_header\n");

    // 视频
    AVStream *video_st = avformat_new_stream(s, NULL);
    if (!video_st)
        return AVERROR(ENOMEM);
    video_st->codecpar->codec_type = AVMEDIA_TYPE_VIDEO;
    video_st->codecpar->codec_id = AV_CODEC_ID_H264;
    // video_st->need_parsing = AVSTREAM_PARSE_FULL_RAW;
    // video_st->codecpar->width = 1280;
    // video_st->codecpar->height = 720;
    // video_st->codecpar->format = AV_PIX_FMT_YUV420P;
    // video_st->codecpar->sample_aspect_ratio = av_make_q(1, 1000000);
    
    video_st->index = 0;

    // 音频流
    AVStream *audio_st = avformat_new_stream(s, NULL);
    if (!video_st)
        return AVERROR(ENOMEM);
    audio_st->codecpar->codec_type = AVMEDIA_TYPE_AUDIO;
    audio_st->codecpar->codec_id = AV_CODEC_ID_AAC;
    audio_st->index = 1;
//    avpriv_set_pts_info(audio_st, 64, 1, 28224000);
    avpriv_set_pts_info(audio_st, 64, 1, 90000);


    s->start_time = 0;

    return 0;
}

static int js_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    av_log(NULL, AV_LOG_ERROR,"js_read_packet\n");
    int ret = 0;
    // data_context
    JSh264decContext *h264Context = s->priv_data;

    // 读取头信息
    uint32_t header_must = 0;
    ret = avio_read(s->pb, &header_must, 4);
    if (ret != 4)
        return AVERROR(EIO);
    header_must = ntohl(header_must);
    // printf("header_must: read 4 ret->%d\n", ret);

    // 获取帧类型
    JSh264FrameType frame_type = header_must >> 24 & 0xFF;
    
    // 帧长度
    uint32_t frame_total_size = header_must & 0xFFFFFF;
    // printf("frame_total_size-->%ld\n", frame_total_size);

    // TODO: 两个业务数据帧的处理
    if (frame_type == eFrameTypeCustomProtocol || frame_type == eFrameTypeStatistic)
    {
        // probuf处理
        avio_skip(s->pb, frame_total_size - 4);
        return 0;
    }

    // 帧序号
    uint32_t frame_sequence = 0;
    ret = avio_read(s->pb, &frame_sequence, 4);
    // printf("frame_sequence: read 4 ret->%d\n", ret);
    if (ret != 4)
        return AVERROR(EIO);
    frame_sequence = ntohl(frame_sequence);

    // 时间戳 附加数据长度
    uint64_t ts_and_ext = 0;
    ret = avio_read(s->pb, &ts_and_ext, 8);
    // printf("ts_and_ext: read 8 ret->%d\n", ret);
    if (ret != 8)
        return AVERROR(EIO);
    // 大端转小端
    ts_and_ext = ntohlll(ts_and_ext);

    // 时间戳
    int64_t timestamp = ts_and_ext >> 16 & 0xffffffffffff;
    av_log(NULL, AV_LOG_ERROR,"timestamp---->%lld\n", timestamp);

    // 附加数据长度
    uint16_t ext_header_len = ts_and_ext & 0xffff;

    // -4 头长度
    // -4 帧序号
    // -8 时间戳、附加数据len信息
    // 获取帧数据长度
    int pkt_size = frame_total_size - 16 - ext_header_len;

    // printf("[data checker], frame_total_size-->%d, frame_sequence-->%d , timestamp-->%lld, ext_header_len-->%ld\n", frame_total_size, frame_sequence, timestamp, ext_header_len);
    av_log(NULL, AV_LOG_ERROR,"pkt_size---->%d\n", pkt_size);
    // 附加数据读取
    if (ext_header_len > 0)
    {
        assert(ext_header_len % 4 == 0);
        // 每4个字节储存一类数据，分辨率、帧率、码率、音频描述
        uint8_t ext_bytes = ext_header_len / 4;
        uint8_t read_idx = 0;
        
        // 附加数据
        av_log(NULL, AV_LOG_ERROR,"附加数据 start malloc -- ext_header_len == %d\n",ext_header_len);
        void* ext_data = (void*)malloc(ext_header_len);
        if (ext_data == NULL)
            return AVERROR(ENOMEM);
        
        // printf("附加数据 end malloc\n");
        ret = avio_read(s->pb, ext_data, ext_header_len);
        // printf("ts_and_ext: read %lld ret->%d\n", ext_header_len, ret);
        // printf("附加数据 end read %d\n", ret);
        // TODO: 附加数据读取
        // while (read_idx < ext_bytes && ext_bytes > 0)
        // {
        //     // uint32_t ext_byte_data = 0;
        //     memcpy(&ext_byte_data, ext_data + read_idx*4, 4);
        //     printf("附加数据: idx->%d\n", read_idx*4);
        //     ext_byte_data = ntohll(ext_byte_data);
            

        //     uint8_t ext_data_header = ext_byte_data >> 24 & 0xFF;
        //     printf("附加数据字节头： %.2x\n", ext_data_header);

        //     read_idx++;
        // }
        
        
        free(ext_data);
        // printf("附加数据读取完成\n");
    }
    
    // printf("[data checker] pkt_size:%d\n", pkt_size);
    // 初始化帧
    if (av_new_packet(pkt, pkt_size) < 0)
        return AVERROR(ENOMEM);

    // 普通读取帧数据
    ret = avio_read(s->pb, pkt->data, pkt_size);
    if (ret != pkt_size)
        return AVERROR(EIO);
    
//    printf("[index-%d]pkt->data: read %lld ret->%d\n", probe_count++, pkt_size, ret);
    //printf("[probe_count: %d]帧数据读取结果: %d, pkt_size: %d \n", probe_count++, ret, pkt_size);
    
    if (h264Context->a_first_time == 0 || h264Context->a_first_time > timestamp)
        h264Context->a_first_time = timestamp;
    
    if (frame_type == eFrameTypeAudio)
    {
//        if (h264Context->a_first_time == 0 || h264Context->a_first_time > timestamp)
//            h264Context->v_first_time = h264Context->a_first_time = timestamp;

        pkt->stream_index = 1;
        pkt->codec_id = AV_CODEC_ID_AAC;
        pkt->dts = pkt->pts = FFMAX(0, timestamp - h264Context->a_first_time) * 90;
    }
    else
    {
//        if (h264Context->v_first_time == 0 || h264Context->v_first_time > timestamp)
//            h264Context->v_first_time = h264Context->a_first_time = timestamp;

        pkt->stream_index = 0;
        pkt->codec_id = AV_CODEC_ID_H264;
        pkt->dts = pkt->pts = FFMAX(0, timestamp - h264Context->a_first_time) * 90;
    }

    // I帧
    if (frame_type == eFrameTypeIFrame)
        pkt->flags |= AV_PKT_FLAG_KEY;
    pkt->timestamp = timestamp;
    pkt->pos = avio_tell(s->pb);

//end:

    // 写入本地测试
    // if (s_pFile != NULL)
    // {
    //     fwrite(pkt->data, 1, pkt_size, s_pFile);
    //     fflush(s_pFile);
    //     printf("写入完成\n");
    // }

    return ret;
}

/*
#define RAW_HEADER_SIZE 16
static int js_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    int ret = 0;
    printf("js_read_packet----------------------- \n");
    uint8_t *header_buf = malloc(RAW_HEADER_SIZE);
    ret = avio_read(s->pb, header_buf, RAW_HEADER_SIZE);
    
    // 包长度
    uint32_t header_must = 0;
    memcpy(&header_must, header_buf, 4);
    header_must = ntohl(header_must);
    uint32_t data_len = header_must & 0xFFFFFF;

    // 附加数据
    uint64_t ts_and_ext = 0;
    memcpy(&ts_and_ext, header_buf + 8, 8);
    ts_and_ext = ntohll(ts_and_ext);

    // 时间戳
    uint64_t timestamp = ts_and_ext >> 16 & 0xffffffffffff;
    // 附加数据长度
    uint16_t ext_len = ts_and_ext & 0xffff;

    int pkt_size = data_len - ext_len - RAW_HEADER_SIZE;
    printf("[jsh264dec 1] data_len:%d, ext_len: %d, pkt_size: %d, ret: %d\n", data_len, ext_len, pkt_size, ret);

    // 初始化帧
    if (av_new_packet(pkt, pkt_size) < 0)
        return AVERROR(ENOMEM);
    
    // 读取
    ret = avio_read(s->pb, pkt->data, pkt_size);

    printf("[jsh264dec 2] data_len:%d, ext_len: %d, pkt_size: %d, ret: %d\n", data_len, ext_len, pkt_size, ret);

    if (header_buf[0] == 0x05 || header_buf[0] == 0x04)
    {
        av_packet_unref(pkt);
        free(header_buf);
        return 0;
    }
    else if (header_buf[0] == 0x06)
    {
        pkt->stream_index = 1;
        pkt->codec_id = AV_CODEC_ID_AAC;
    }
    else
    {
        pkt->stream_index = 0;
        pkt->codec_id = AV_CODEC_ID_H264;
    }
    
    if (header_buf[0] == 0x00)
        pkt->flags |= AV_PKT_FLAG_KEY;

    // usleep(100*1000);

end:

    free(header_buf);
    return 0;
}
*/

/*
#define RAW_PACKET_SIZE 19
static int js_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    int ret;
    int header_size = RAW_PACKET_SIZE;
    // 读取19个头字节
    uint8_t *nBuff = NULL;
    // sps/pps 内容
    uint8_t *p_sps_pps, *p_sps, *p_pps;
    // sps/pps 长度
    int sps_size, pps_size, sps_pps_size;
    // dts pts
    int64_t dts, pts = AV_NOPTS_VALUE;

    // data_context
    JSh264decContext *h264Context = s->priv_data;
    
    
    // 每次先读取19字节长度封装的头信息
    // printf("%pre_read: orig_buffer_size--->%d\n", s->pb->orig_buffer_size);
    nBuff = av_malloc(RAW_PACKET_SIZE);
    ret = avio_read_partial(s->pb, nBuff, RAW_PACKET_SIZE);
    if (ret < 0){
        free(nBuff);
        return 0;
    }

    assert(ret == RAW_PACKET_SIZE);
    
    // 从字节头解析出数据的长度
    uint32_t byte_length = 0;
    memcpy(&byte_length, nBuff + 7, 4);
    byte_length = ntohl(byte_length);
    // printf("[info:%d] byte_length--->%d, pkt_type--->%s \n", probe_count, byte_length, nBuff[5] == 0x01 ? "视频":"音频");
    // printf("[info:%d] %.2x %.2x %.2x %.2x %.2x %.2x %.2x end\n", probe_count++, nBuff[0], nBuff[1], nBuff[2], nBuff[3], nBuff[4], nBuff[5], nBuff[6]);
    
    // 时间戳读取
    memcpy(&pts, nBuff + 11, 8);
    pts = ntohll(pts);

    // 读取sps、pps, I 帧处理
    if (nBuff[5] == 0x01 && nBuff[6] == 0x00)
    {
        // 获取sps 
        sps_size = byte_length;
        p_sps = malloc(sps_size); 
        ret = avio_read_partial(s->pb, p_sps, sps_size);
        if (ret < 0){
            free(nBuff);
            return 0;
        }

        // 获取pps,重新获取长度
        //free(nBuff);
        //nBuff = (uint8_t *)av_realloc(nBuff, RAW_PACKET_SIZE);
        memset(nBuff,0x00,19);
        ret = avio_read_partial(s->pb, nBuff, RAW_PACKET_SIZE);
        memcpy(&byte_length, nBuff + 7, 4);
        byte_length = ntohl(byte_length);
        // printf("[info:%d -- 1] byte_length------>%d \n", probe_count, byte_length);
        printf("[info:%d -- 1] %.2x %.2x %.2x %.2x %.2x %.2x  %.2x end\n", probe_count++, nBuff[0], nBuff[1], nBuff[2], nBuff[3], nBuff[4], nBuff[5], nBuff[6]);

        // 获取pps
        pps_size = byte_length;
        p_pps = malloc(pps_size);
        // ret = avio_read_partial(s->pb, p_pps, pps_size);
        ret = avio_read_partial(s->pb, p_pps, pps_size);
        if (ret < 0){
            free(nBuff);
            return 0;
        }
        
        sps_pps_size =  pps_size+sps_size;
        p_sps_pps = malloc(sps_pps_size);
        memcpy(p_sps_pps, p_sps, sps_size);
        memcpy(p_sps_pps + sps_size, p_pps, pps_size);

        // printf("sps_pps_size--->%d + %d = %d \n", sps_size, pps_size, sps_pps_size);

        // avio_skip(s->pb, sps_pps_size);
        free(p_sps);
        free(p_pps);
        //free(nBuff);
        //nBuff = NULL;

        // 读取I帧头
        //nBuff = (uint8_t *)av_realloc(nBuff, RAW_PACKET_SIZE);
        memset(nBuff,0x00,19);
        ret = avio_read(s->pb, nBuff, RAW_PACKET_SIZE);
        memcpy(&byte_length, nBuff + 7, 4);
        byte_length = ntohl(byte_length);

        // 时间戳读取
        memcpy(&pts, nBuff + 11, 8);
        pts = ntohll(pts);

        // 初始化第一次加载出来的时间戳
        if (h264Context->first_time == 0)
        {
            h264Context->first_time = pts;
        }
        
        printf("[info:%d -- I帧头] %.2x %.2x %.2x %.2x %.2x %.2x  %.2x end\n", probe_count++, nBuff[0], nBuff[1], nBuff[2], nBuff[3], nBuff[4], nBuff[5], nBuff[6]);

    
        // 读取I帧
        int pkt_total_size = byte_length + sps_pps_size;
        if (av_new_packet(pkt, pkt_total_size) < 0)
            return AVERROR(ENOMEM);
        memcpy(pkt->data, p_sps_pps, sps_pps_size);
        
        ret = avio_read_partial(s->pb, pkt->data + sps_pps_size, byte_length);
        if (ret < 0) {
            av_packet_unref(pkt);
            return ret;
        }
        // av_shrink_packet(pkt, pkt_total_size);
        pkt->pos = avio_tell(s->pb);
        pkt->stream_index = 0;
        pkt->codec_id = AV_CODEC_ID_H264;
        pkt->pts = (pts - h264Context->first_time) > 0 ? pts - h264Context->first_time : 0;
        // printf("byte_length: %d, sps_pps_size: %d, dataSize: %d\n", byte_length, sps_pps_size, pkt->size);
        // printf("file_path: %s\n", s->file_path);
        // FILE *write_fd = fopen(s->file_path, "wb+");
        // fwrite(pkt->data,1, pkt_total_size, write_fd);
        // fflush(write_fd);

        

        free(p_sps_pps);
        goto end;
    }
    
    printf("[info] type:%s length:%d\n", nBuff[5] == 0x01 ? "video":"audio", byte_length);

    if (nBuff[5] == 0x01) // 视频
    {

        // 根据长度读取裸流数据
        if (av_new_packet(pkt, byte_length) < 0)
            return AVERROR(ENOMEM); 
        // 填充packet
        // ret = avio_read_partial(s->pb, pkt->data, byte_length);
        ret = avio_read_partial(s->pb, pkt->data, byte_length);
        if (ret < 0) {
            av_packet_unref(pkt);
            return ret;
        }
        av_shrink_packet(pkt, ret);

        pkt->pos = avio_tell(s->pb);
        pkt->stream_index = 0;
        pkt->codec_id = AV_CODEC_ID_H264;
        pkt->pts = (pts - h264Context->first_time) > 0 ? pts - h264Context->first_time : AV_NOPTS_VALUE;

        // av_get_packet
    }
    else if(nBuff[5] == 0x02)// 音频
    {
        int audio_pkt_len = byte_length + 7;
        if (av_new_packet(pkt, audio_pkt_len) < 0)
            return AVERROR(ENOMEM); 
        // ret = avio_read_partial(s->pb, pkt->data, audio_pkt_len);
        ret = avio_read_partial(s->pb, pkt->data, audio_pkt_len);
        if (ret < 0) {
            printf("[error] avio_read_partial ret->%d \n", ret);
            av_packet_unref(pkt);
            return ret;
        }
        av_shrink_packet(pkt, ret);

        pkt->pos = avio_tell(s->pb);
        pkt->stream_index = 1;
        pkt->codec_id = AV_CODEC_ID_AAC;
        pkt->pts = (pts - h264Context->first_time) > 0 ? pts - h264Context->first_time : AV_NOPTS_VALUE;
        // av_packet_unref(pkt);
        // free(nBuff);
    }
    
end:

    pkt->dts = pkt->pts;

    if (nBuff[6] == 0x02 && pkt)
    {
        // printf("I 帧 %d \n", byte_length);
        pkt->flags |= AV_PKT_FLAG_KEY;
    }

    if (nBuff != NULL){
        free(nBuff);
    }

    return 0;
}*/

static int js_read_seek(AVFormatContext *s, int stream_index,
                         int64_t ts, int flags)
{
    printf("AVFormatContext js_read_seek \n");
    JSh264decContext *h264 = s->priv_data;
    h264->v_first_time = 0;
    h264->a_first_time = 0;
    return avio_seek_time(s->pb, stream_index, ts, flags);;
}

static const AVClass live_jsh264_class = {
    .class_name = "live_jsh264dec",
    .item_name  = av_default_item_name,
    .version    = LIBAVUTIL_VERSION_INT,
};

static int js_read_close(AVFormatContext *s)
{
    printf("demuxer -- js_close");

    return 0;
}

AVInputFormat ff_live_jsh264_demuxer = {
    .name           = "jsh264dec",
    .long_name      = "live jsh264dec",
    .priv_data_size = sizeof(JSh264decContext),
    .read_probe     = js_h264_probe,
    .read_header    = js_read_header,
    .read_packet    = js_read_packet,
    .read_close     = js_read_close,
    .extensions     = "jsh264",
    .priv_class     = &live_jsh264_class,
    .flags          = AVFMT_TS_DISCONT
};


#endif /* jsh264dec_h */
