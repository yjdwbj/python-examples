#!/opt/stackless-279/bin/python
#-*- coding:utf-8 -*-
import random
import argparse
import numpy as np
from numpy import *
from numpy.random import randint
import random
import cStringIO
import string
import tornado.httpserver
import tornado.ioloop
import tornado.web
import sys 
if not sys.getfilesystemencoding():
    sys.getfilesystemencoding = lambda: 'UTF-8'

import matplotlib.font_manager as mf
from scipy import ndimage
from scipy.special import *
from PIL import Image,ImageDraw,ImageFont,ImageFilter,ImageEnhance
import redis
import threading
import time

flst = mf.findSystemFonts(fontpaths='/usr/share/fonts/truetype',fontext='ttf')
flen = len(flst)-1


WIDTH = 125
HEIGHT = 36
FONT_SIZE = 28

imgpool = {}
IMG_SIZE=1000

#def code_generator(size=6,chars=string.ascii_lowercase+string.digits):
def code_generator(size=6,chars=string.digits):
    return ''.join(random.SystemRandom().choice(chars) for _ in xrange(size))

def bytescale(data, cmin=None, cmax=None, high=255, low=0):
    """
    Byte scales an array (image).

    Byte scaling means converting the input image to uint8 dtype and scaling
    the range to ``(low, high)`` (default 0-255).
    If the input image already has dtype uint8, no scaling is done.

    Parameters
    ----------
    data : ndarray
        PIL image data array.
    cmin : scalar, optional
        Bias scaling of small values. Default is ``data.min()``.
    cmax : scalar, optional
        Bias scaling of large values. Default is ``data.max()``.
    high : scalar, optional
        Scale max value to `high`.  Default is 255.
    low : scalar, optional
        Scale min value to `low`.  Default is 0.

    Returns
    -------
    img_array : uint8 ndarray
        The byte-scaled array.

    Examples
    --------
    >>> from scipy.misc import bytescale
    >>> img = array([[ 91.06794177,   3.39058326,  84.4221549 ],
    ...              [ 73.88003259,  80.91433048,   4.88878881],
    ...              [ 51.53875334,  34.45808177,  27.5873488 ]])
    >>> bytescale(img)
    array([[255,   0, 236],
           [205, 225,   4],
           [140,  90,  70]], dtype=uint8)
    >>> bytescale(img, high=200, low=100)
    array([[200, 100, 192],
           [180, 188, 102],
           [155, 135, 128]], dtype=uint8)
    >>> bytescale(img, cmin=0, cmax=255)
    array([[91,  3, 84],
           [74, 81,  5],
           [52, 34, 28]], dtype=uint8)

    """
    if data.dtype == uint8:
        return data

    if high < low:
        raise ValueError("`high` should be larger than `low`.")

    if cmin is None:
        cmin = data.min()
    if cmax is None:
        cmax = data.max()

    cscale = cmax - cmin
    if cscale < 0:
        raise ValueError("`cmax` should be larger than `cmin`.")
    elif cscale == 0:
        cscale = 1

    scale = float(high - low) / cscale
    bytedata = (data * 1.0 - cmin) * scale + 0.4999
    bytedata[bytedata > high] = high
    bytedata[bytedata < 0] = 0
    return cast[uint8](bytedata) + cast[uint8](low)


def toimage(arr, high=255, low=0, cmin=None, cmax=None, pal=None,
            mode=None, channel_axis=None):
    """Takes a numpy array and returns a PIL image.

    The mode of the PIL image depends on the array shape and the `pal` and
    `mode` keywords.

    For 2-D arrays, if `pal` is a valid (N,3) byte-array giving the RGB values
    (from 0 to 255) then ``mode='P'``, otherwise ``mode='L'``, unless mode
    is given as 'F' or 'I' in which case a float and/or integer array is made.

    Notes
    -----
    For 3-D arrays, the `channel_axis` argument tells which dimension of the
    array holds the channel data.

    For 3-D arrays if one of the dimensions is 3, the mode is 'RGB'
    by default or 'YCbCr' if selected.

    The numpy array must be either 2 dimensional or 3 dimensional.

    """
    data = asarray(arr)
    if iscomplexobj(data):
        raise ValueError("Cannot convert a complex-valued array.")
    shape = list(data.shape)
    valid = len(shape) == 2 or ((len(shape) == 3) and
                                ((3 in shape) or (4 in shape)))
    if not valid:
        raise ValueError("'arr' does not have a suitable array shape for "
                         "any mode.")
    if len(shape) == 2:
        shape = (shape[1], shape[0])  # columns show up first
        if mode == 'F':
            data32 = data.astype(np.float32)
            image = Image.frombytes(mode, shape, data32.tostring())
            return image
        if mode in [None, 'L', 'P']:
            bytedata = bytescale(data, high=high, low=low,
                                 cmin=cmin, cmax=cmax)
            image = Image.frombytes('L', shape, bytedata.tostring())
            if pal is not None:
                image.putpalette(asarray(pal, dtype=uint8).tostring())
                # Becomes a mode='P' automagically.
            elif mode == 'P':  # default gray-scale
                pal = (arange(0, 256, 1, dtype=uint8)[:, newaxis] *
                       ones((3,), dtype=uint8)[newaxis, :])
                image.putpalette(asarray(pal, dtype=uint8).tostring())
            return image
        if mode == '1':  # high input gives threshold for 1
            bytedata = (data > high)
            image = Image.frombytes('1', shape, bytedata.tostring())
            return image
        if cmin is None:
            cmin = amin(ravel(data))
        if cmax is None:
            cmax = amax(ravel(data))
        data = (data*1.0 - cmin)*(high - low)/(cmax - cmin) + low
        if mode == 'I':
            data32 = data.astype(np.uint32)
            image = Image.frombytes(mode, shape, data32.tostring())
        else:
            raise ValueError(_errstr)
        return image

    # if here then 3-d array with a 3 or a 4 in the shape length.
    # Check for 3 in datacube shape --- 'RGB' or 'YCbCr'
    if channel_axis is None:
        if (3 in shape):
            ca = np.flatnonzero(asarray(shape) == 3)[0]
        else:
            ca = np.flatnonzero(asarray(shape) == 4)
            if len(ca):
                ca = ca[0]
            else:
                raise ValueError("Could not find channel dimension.")
    else:
        ca = channel_axis

    numch = shape[ca]
    if numch not in [3, 4]:
        raise ValueError("Channel axis dimension is not valid.")

    bytedata = bytescale(data, high=high, low=low, cmin=cmin, cmax=cmax)
    if ca == 2:
        strdata = bytedata.tostring()
        shape = (shape[1], shape[0])
    elif ca == 1:
        strdata = transpose(bytedata, (0, 2, 1)).tostring()
        shape = (shape[2], shape[0])
    elif ca == 0:
        strdata = transpose(bytedata, (1, 2, 0)).tostring()
        shape = (shape[2], shape[1])
    if mode is None:
        if numch == 3:
            mode = 'RGB'
        else:
            mode = 'RGBA'

    if mode not in ['RGB', 'RGBA', 'YCbCr', 'CMYK']:
        raise ValueError(_errstr)

    if mode in ['RGB', 'YCbCr']:
        if numch != 3:
            raise ValueError("Invalid array shape for mode.")
    if mode in ['RGBA', 'CMYK']:
        if numch != 4:
            raise ValueError("Invalid array shape for mode.")

    # Here we know data and mode is correct
    image = Image.frombytes(mode, shape, strdata)
    return image


class ImageHandler(tornado.web.RequestHandler):
    def initialize(self,rdb):
        self.redis = rdb

    def get(self):
        self.set_header("Content-type","image/png")
        key = random.choice(imgpool.keys())
        self.redis.setex(self.request.remote_ip,key,600) #十分钟有效
        self.write(imgpool.get(key))

def timer_to_refresh(d):
    while 1:
        d.clear()
        for i in xrange(IMG_SIZE):
            txt = code_generator()
            streamio = cStringIO.StringIO()
            img = toimage(make_text_image(WIDTH,HEIGHT,0,-3,FONT_SIZE,\
                    127,str(txt)))
	    img.save(streamio,'PNG')
            d[txt] =  streamio.getvalue()
            streamio.close()
        time.sleep(3600)


class ImageInit():
    def __init__(self,redis_ip='127.0.0.1',redis_port=6379,redis_pass=None):
#        self.redis = redis.Redis(host=redis_ip,port=redis_port,db=4,\
#            password=redis_pass)
#        try:
#            type(self.redis.info())
#        except ResponseError:
#            print u"连接Redis服务器出错,不能连接程".encode('utf8')
#            return
#
#        n = time.time()
#        for i in xrange(IMG_SIZE):
#            txt = code_generator()
#            streamio = cStringIO.StringIO()
#            imsave(streamio,make_text_image(WIDTH,HEIGHT,0,-3,FONT_SIZE,randint(100,157),str(txt)))
#            imgpool[txt] = streamio
#        print "create %d images,time is" % IMG_SIZE,time.time() - n
        update_th = threading.Thread(target = timer_to_refresh,args=(imgpool,))
        update_th.Daemon = True
        update_th.start()
        
        


def make_text_image(width,height,x,y,size,th,text):
    img = Image.new("RGB",(width,height),(255,255,255))
    font = ImageFont.truetype(flst[randint(0,flen)],size)
    draw = ImageDraw.Draw(img)
    draw.text((x,y),text,font = font,fill=255)
    rate = int(width * height * 0.2)
    for i in xrange(rate):
        cp = (randint(0,255),randint(0,255),randint(0,255))
        draw.point((randint(0,width),randint(0,height)),fill=cp)

    for i in xrange(5):
        x = (randint(0,width),randint(0,height))
        y = (randint(0,width),randint(2,height))
        cp = (randint(0,255),randint(0,255),randint(0,255))
        draw.line([x,y],fill=cp)
    params = [1 - float(randint(1,2))/100,
            0,
            0,
            0,
            1-float(randint(1,20))/100,
            float(randint(1,2)) /500,
            0.001,
            float(randint(1,2))/500
            ]
    img = img.transform((width,height),Image.PERSPECTIVE,params)
    img = img.filter(ImageFilter.EDGE_ENHANCE_MORE)

    return ndimage.gaussian_filter(np.array(img),sigma=0.9)

def handle_argments():
    parser = argparse.ArgumentParser(
        formatter_class = argparse.ArgumentDefaultsHelpFormatter
        )
    parser.add_argument('--redis_ip',action='store',dest='redis_ip',\
            type=str,help=u'redis server address'.encode('utf8'))
    parser.add_argument('--redis_port',action='store',dest='redis_port',\
            type=int,default=6379,help=u'redis servre port'.encode('utf8'))
    parser.add_argument('--redis_pass',action='store',dest='redis_pass',\
            type=str,default=None,help=u'redis auth password'.encode('utf8'))
    parser.add_argument('--version',action='version',version='0.1.0')

    args = parser.parse_args()


    if not args.redis_ip:
        print u'缺少运行必须参数 --redis_ip'.encode('utf-8')
        parser.parse_args(['-h'])
        sys.exit(1);
    return args

if __name__ == '__main__':
    args = handle_argments()
    rdb  = redis.Redis(host=args.redis_ip,port=args.redis_port,db=4,\
        password=args.redis_pass)
    try:
         type(rdb.info())
    except:
        print u"连接Redis服务器出错,不能连接程".encode('utf8')
        sys.exit(0)
    ImageInit()
    application = tornado.web.Application([(r"/",ImageHandler,dict(rdb=rdb)),])
    http_srv = tornado.httpserver.HTTPServer(application)
    http_srv.listen(8899)
    tornado.ioloop.IOLoop.instance().start()

