//
//  jsh264.h
//  testwsfile
//
//  Created by Zaki on 2020/1/25.
//  Copyright © 2020 Zaki. All rights reserved.
//

#ifndef jsh264_h
#define jsh264_h

#include <stdio.h>
#include "libavformat/avformat.h"

static int ff_jsh264_ws_connect(AVFormatContext *s);

static int ff_jsh264_ws_close(AVFormatContext *s);

#endif /* jsh264_h */
