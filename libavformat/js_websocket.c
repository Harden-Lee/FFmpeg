#include "js_websocket.h"

static url_t *_parse_url(const char *url, url_t *ret)
{
    char buff[256] = {0};
    int iret = sscanf(url, "%7[^://]%*c%*c%*c%127[^:]%*c%d/%1023[^?]%*c%1023s", ret->scheme, ret->hostname, &ret->port, ret->path, ret->query);
    if (2 == iret)
    {
        iret = sscanf(url, "%7[^://]%*c%*c%*c%127[^/]/%1023[^?]%*c%1023s", ret->scheme, ret->hostname, ret->path, ret->query);
        
        if(!strncmp(ret->scheme, "wss", 3)){
            ret->port = 443;
        }else{
            ret->port = 80;
        }
    }
    sprintf(buff, "/%s", ret->path);
    sprintf(ret->path, "%s", buff);
    av_log(NULL, AV_LOG_ERROR,"ret path == %s\n",ret->path);
    return ret;
}

static int32_t _recv_line(wsContext_t *ctx, char *buff)
{
    int32_t i = 0;
    int32_t iret = 0;
    uint8_t c = 0;
    int timeOut = 0;
    while ('\n' != c)
    {
        if (ctx->ssl_ctx) {
            iret = (int32_t)ws_ssl_read(ctx->ssl_ctx, &c, 1);
        }else{
#ifdef __APPLE__
            iret = (int32_t)recv(ctx->fd, &c, 1, 0);
#else
            iret = (int32_t)recv(ctx->fd, &c, 1, MSG_NOSIGNAL);
#endif
        }
        
        if (iret <= 0 ) {
            timeOut += 10;
            if(timeOut > 2000)
            {
                return -1;
            }
            delayms(10);  //1ms
        }else{
            if (i >= 256) {
                return -1;
            }
            buff[i++] = c;
        }
    }

    return i - 1;
}

static int32_t _validate_headers(wsContext_t *ctx, char *key)
{
    av_log(NULL, AV_LOG_ERROR,"i_validate_headers\n");
    int32_t iret = 0;
    char buff[256] = {0};
    uint32_t status = 0;
    char value[256] = {0};
    char result[256] = {0};
    char header_k[256] = {0};
    char header_v[256] = {0};
    char base64str[256] = {0};
    int32_t base64_len = 0;
    uint8_t sha1[20] = {0};

    if (_recv_line(ctx, buff) < 0)
    {
        iret = -1;
        goto end;
    }
    sscanf(buff, "%*s%d", &status);
    if (status != 101)
    {
        iret = -1;
        goto end;
    }
    while (strcmp(buff, "\r\n") != 0)
    {
        memset(buff, 0, 256);
        memset(header_k, 0, 256);
        memset(header_v, 0, 256);
        if (_recv_line(ctx, buff) < 0)
        {
            iret = -1;
            goto end;
        }
        sscanf(buff, "%256s%256s", header_k, header_v);
        if (strncmp(header_k, "Sec-WebSocket-Accept:", 256) == 0)
        {
            snprintf(result, 256, "%s", header_v);
        }
    }
    snprintf(value, 256, "%s%s", key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    sha1Buff(value, strlen(value), sha1);
    base64_encode(sha1, 20, (uint8_t *) base64str, &base64_len);
    if (strncmp(str2lower(base64str), str2lower(result), 256) != 0)
    {
        iret = -1;
        goto end;
    }

end:
    return iret;
}

static int32_t _handshake(wsContext_t *cxt, url_t source)
{
    int offset = 0;
    char header_str[512] = {0};
    offset += sprintf(header_str + offset, "GET %s HTTP/1.1\r\n", source.path);
    offset += sprintf(header_str + offset, "Upgrade: websocket\r\n");
    offset += sprintf(header_str + offset, "Connection: Upgrade\r\n");
    offset += sprintf(header_str + offset, "Host: %s:%u\r\n", source.hostname, source.port);
    offset += sprintf(header_str + offset, "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n");
    offset += sprintf(header_str + offset, "Sec-WebSocket-Version: 13\r\n\r\n");
    
    if (!strncmp(source.scheme, "wss", 3)) {
        cxt->ssl_ctx = ws_ssl_handshake(cxt, source.hostname, source.ssl_key, source.ssl_crt,1);
        if (!cxt->ssl_ctx) {
            return -1;
        }
        if (ws_ssl_write(cxt->ssl_ctx, (uint8_t *)header_str, offset)) {
            return -1;
        }
    }else {
#ifdef __APPLE__
        int ret = send(cxt->fd, header_str, offset, 0);
#else
        int ret = send(cxt->fd, header_str, offset, MSG_NOSIGNAL);
#endif
        av_log(NULL, AV_LOG_ERROR,"send -- ret == %d offset %d\n",ret,offset);
    }
    
    return _validate_headers(cxt, "x3JJHMbDL1EzLkh9GBhXDw==");
}

static int32_t _create_frame(ANBF_t *frame, int fin, int rsv1, int rsv2, int rsv3, int opcode, int has_mask, void *data, int len)
{
    frame->fin = fin;
    frame->rsv1 = rsv1;
    frame->rsv2 = rsv2;
    frame->rsv3 = rsv3;
    frame->mask = has_mask;
    frame->opcode = opcode;
    frame->data = data;
    frame->length = len;

    return 0;
}

static void *_format_frame(ANBF_t *frame, int32_t *size)
{
    int offset = 0;
    char *frame_header = NULL;
    uint16_t header =
            (frame->fin << 15) |
            (frame->rsv1 << 14) |
            (frame->rsv2 << 13) |
            (frame->rsv3 << 12) |
            (frame->opcode << 8);

    char byteLen = 0;
    if (frame->length < LENGTH_7)
    {
        header |= frame->mask << 7 | (uint8_t) frame->length;
    }
    else if (frame->length < LENGTH_16)
    {
        header |= frame->mask << 7 | 0x7e;
        byteLen = 2;
    }
    else
    {
        header |= frame->mask << 7 | 0x7f;
        byteLen = 8;
    }

    frame_header = (char *) malloc(sizeof (header) + byteLen + (uint32_t) frame->length);
    header = htons(header);
    memcpy(frame_header + offset, &header, sizeof (header));
    offset += sizeof (header);
    if (byteLen == 2)
    {
        uint16_t len = htons((uint16_t) frame->length);
        memcpy(frame_header + offset, &len, sizeof (len));
        offset += sizeof (len);
    }
    else if (byteLen == 8)
    {
        uint64_t len = htonlll(frame->length);
        memcpy(frame_header + offset, &len, sizeof (len));
        offset += sizeof (len);
    }
    memcpy(frame_header + offset, frame->data, (uint32_t) frame->length);
    *size = offset + (uint32_t) frame->length;
    return frame_header;
}

static void *_ANBFmask(uint32_t mask_key, void *data, int32_t len)
{
    int32_t i = 0;
    uint8_t *_m = (uint8_t *) & mask_key;
    uint8_t *_d = (uint8_t *) data;
    for (; i < len; i++)
    {
        _d[i] ^= _m[i % 4];
    }
    return _d;
}

static int32_t _recv_restrict(wsContext_t *ctx, void *buff, int32_t size)
{
    int32_t offset = 0;
    int32_t iret = 0;
    int timeOut = 0;
    while (offset < size)
    {
        if (ctx->ssl_ctx) {
            iret = ws_ssl_read(ctx->ssl_ctx, ((uint8_t *) buff) + offset, (int32_t) (size - offset));
        }else {
#ifdef __APPLE__
            iret = recv(ctx->fd, ((char *) buff) + offset, (int32_t) (size - offset), 0);
#else
            iret = recv(ctx->fd, ((char *) buff) + offset, (int32_t) (size - offset), MSG_NOSIGNAL);
#endif
        }
        if (iret > 0)
        {
            offset += iret;
        }
        else
        {
            timeOut += 10;
            if(timeOut > 2000)
            {
                return -1;
            }
            delayms(10);  //10ms
        }
    }
    return offset;
}

static int32_t _recv_frame(wsContext_t *ctx, ANBF_t *frame)
{
    uint8_t b1, b2, fin, rsv1, rsv2, rsv3, opcode, has_mask;
    uint64_t frame_length = 0;
    uint16_t length_data_16 = 0;
    uint64_t length_data_64 = 0;
    uint32_t frame_mask = 0;
    uint8_t length_bits = 0;
    uint8_t frame_header[2] = {0};
    int32_t iret = 0;
    char *payload = NULL;

    iret = _recv_restrict(ctx, &frame_header, 2);
    av_log(NULL, AV_LOG_ERROR,"1.timeOut iret = %d\n",iret);
    if (iret < 0)
    {
        goto end;
    }
    av_log(NULL, AV_LOG_ERROR,"2.timeOut iret = %d\n",iret);
    b1 = frame_header[0];
    b2 = frame_header[1];
    length_bits = b2 & 0x7f;
    fin = b1 >> 7 & 1;
    rsv1 = b1 >> 6 & 1;
    rsv2 = b1 >> 5 & 1;
    rsv3 = b1 >> 4 & 1;
    opcode = b1 & 0xf;
    has_mask = b2 >> 7 & 1;

    if (length_bits == 0x7e)
    {
        iret = _recv_restrict(ctx, &length_data_16, 2);
        if (iret < 0)
        {
            goto end;
        }

        frame_length = ntohs(length_data_16);
    }
    else if (length_bits == 0x7f)
    {
        iret = _recv_restrict(ctx, &length_data_64, 8);
        if (iret < 0)
        {
            goto end;
        }

        frame_length = ntohlll(length_data_64);
    }
    else
    {
        frame_length = length_bits;
    }

    if (has_mask)
    {
        iret = _recv_restrict(ctx, &frame_mask, 4);
        if (iret < 0)
        {
            goto end;
        }
    }

    if (frame_length > 0)
    {
        payload = (char *) malloc((int32_t) frame_length);
        iret = _recv_restrict(ctx, payload, (int32_t) frame_length);
        if (iret < 0)
        {
            free(payload);
            goto end;
        }
    }

    if (has_mask)
    {
        _ANBFmask(frame_mask, payload, (uint32_t) frame_length);
    }

    return _create_frame(frame, fin, rsv1, rsv2, rsv3, opcode, has_mask, payload, (uint32_t) frame_length);

end:
    return -1;
}

static int32_t _send(wsContext_t *ctx, void *payload, int32_t len, int32_t opcode)
{
    int32_t length = 0;
    int32_t iret = 0;
    ANBF_t frame = {0};
    char *sendData = NULL;
    _create_frame(&frame, 1, 0, 0, 0, opcode, 0, payload, len);
    sendData = (char *) _format_frame(&frame, &length);
    if (ctx->ssl_ctx) {
        iret = ws_ssl_write(ctx->ssl_ctx, (uint8_t *)sendData, length);
    }else{
        iret = (int32_t)send(ctx->fd, sendData, length, 0);
    }
    free(sendData);

    return iret;
}

int32_t sendPing(wsContext_t *ctx, void *payload, int32_t len)
{
    return _send(ctx, payload, len, OPCODE_PING);
}

int32_t sendPong(wsContext_t *ctx, void *payload, int32_t len)
{
    return _send(ctx, payload, len, OPCODE_PONG);
}

int32_t sendCloseing(wsContext_t *ctx, uint16_t status, const char *reason)
{
    char *p = NULL;
    int len = 0;
    char payload[64] = {0};
    status = htons(status);
    p = (char *) &status;
    len = snprintf(payload, 64, "\\x%02x\\x%02x%s", p[0], p[1], reason);
    return _send(ctx, payload, len, OPCODE_CLOSE);
}

int32_t recvData(wsContext_t *ctx, void *buff, int32_t len)
{
    int data_len = -1;
    int iret = -1;
//    ANBF_t _frame = {0};
    ANBF_t *frame = (ANBF_t *)malloc(sizeof(ANBF_t));

    av_log(NULL, AV_LOG_ERROR,"recvData start\n");
    memset(frame, 0, sizeof (ANBF_t));
    iret = _recv_frame(ctx, frame);
    if (iret < 0)
    {
        goto end;
    }
    av_log(NULL, AV_LOG_ERROR,"recvData frame->opcode == %d\n",frame->opcode);
    
    switch (frame->opcode)
    {
        case OPCODE_CLOSE:
        {
            sendCloseing(ctx, STATUS_NORMAL, "");
            wsContextFree(ctx->fd);
            av_log(NULL, AV_LOG_ERROR,"OPCODE_CLOSE close\n");
            goto end;
        }
            break;
        case OPCODE_PING:
        {
            sendPong(ctx, NULL, 0);
            data_len = recvData(ctx,buff,len);
            goto end;
        }
            break;
        case OPCODE_TEXT:
        case OPCODE_BINARY:
        case OPCODE_CONT:{
            if (frame->opcode == OPCODE_CONT)
            {
                goto end;
            }
            if (frame->fin)
            {
                data_len = FFMIN(frame->length,len);
                memcpy(buff, frame->data, data_len);
                goto end;
            }
            else
            {
                data_len = recvData(ctx,buff,len);
                goto end;
            }
        }
            break;
        default:
            goto end;
            break;
    }
end:
   if (frame != NULL) {
       av_log(NULL, AV_LOG_ERROR,"frame free\n");
       if (frame->data != NULL) {
           free(frame->data);
           frame->data = NULL;
       }
       free(frame);
       frame = NULL;
   }
    av_log(NULL, AV_LOG_ERROR,"recvData end\n");
    return data_len;
}

int32_t sendUtf8Data(wsContext_t *ctx, void *data, int32_t len)
{
    return _send(ctx, data, len, OPCODE_TEXT);
}

int32_t sendBinary(wsContext_t *ctx, void *data, int32_t len)
{
    return _send(ctx, data, len, OPCODE_BINARY);
}

int32_t wsCreateConnection(wsContext_t *ctx, const char *url)
{
    url_t purl = {0};
    _parse_url(url, &purl);
    ctx->fd = ut_connect(purl.hostname, purl.port);
    if (ctx->fd > 0) {
        int ret = _handshake(ctx, purl);
        av_log(NULL, AV_LOG_ERROR,"wsCreateConnection --- ret === %d\n",ret);
        if(ret != 0){
            av_log(NULL, AV_LOG_ERROR,"close");
            wsContextFree(ctx);
            return 0;
        }
    }
    return ctx->fd;
}

wsContext_t *wsContextNew()
{
    wsContext_t *ctx = (wsContext_t *) malloc(sizeof (wsContext_t));
    memset(ctx, 0, sizeof (wsContext_t));

    return ctx;
}

int32_t wsContextFree(wsContext_t *ctx)
{
    
    av_log(NULL, AV_LOG_ERROR,"---wsContextFree---\n");
    if (ctx == NULL) {
        return 0;
    }
    
    if (ctx->ssl_ctx != NULL) {
        ws_ssl_close(ctx->ssl_ctx);
    }
    
    close(ctx->fd);
    free(ctx);
    return 0;
}
