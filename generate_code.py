#!/opt/stackless-279/bin/python
import random
from PIL import Image,ImageDraw,ImageFont,ImageFilter,ImageEnhance
import numpy as np
from numpy import *
import matplotlib.pylab as pl
from random import randint
import random
import StringIO
import string
import tornado.httpserver
import tornado.ioloop
import tornado.web
from matplotlib.pyplot import imsave


WIDTH = 125
HEIGHT = 36
FONT_SIZE = 28


def expand_image(img,value,out=None,size=10):
    if out is None:
        w,h = img.shape[:2]
        out = np.zeros((w*size,h*size),dtype=np.uint8)

    tmp = np.repeat(np.repeat(img,size,0),size,1)
    out[:,:] = np.where(tmp,value,out)
    out[::size,:] = 0
    out[:,::size] = 0
    return out

#def code_generator(size=6,chars=string.ascii_lowercase+string.digits):
def code_generator(size=6,chars=string.digits):
    return ''.join(random.SystemRandom().choice(chars) for _ in xrange(size))


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write('<img src="test.png" />')

class ImageHandler(tornado.web.RequestHandler):
    def __init__(self,mdict):
        self.mdict = mdict
        self.set_header("Content-type","image/png")
    def get(self):
        txt = code_generator()
        img = make_text_image(WIDTH,HEIGHT,0,-3,FONT_SIZE,randint(100,157),str(txt))
        pngio = StringIO.StringIO()
        imsave(pngio,img)
        self.write(pngio.getvalue())


application = tornado.web.Application([(r"/",MainHandler),
                                        (r"/test.png",ImageHandler),])
        


def make_text_image(width,height,x,y,size,th,text):
    img = Image.new("RGB",(width,height),(255,255,255))
    font = ImageFont.truetype('wqy-microhei.ttf',size)
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

    #en = ImageEnhance.Contrast(img)
    #img = en.enhance(2)

    return np.asarray(img)>th


def show_image(*imgs):
    for idx,img in enumerate(imgs):
        subplot = 101 + len(imgs)*10 + idx
        pl.subplot(subplot)
        pl.imshow(img,cmap = pl.cm.gray)
        pl.gca().set_axis_off()
    pl.subplots_adjust(0.02,0,0.98,1,0.02,0)

def pca(X):
    """ Principal Component Analysis
    input: X,matrix with training data stored as flattened arrays in rows
    return: projection matrix (with important dimension first),variance
    and mean."""

    # get dimension
    num_data ,dim = X.shape

    #center data
    mean_X = X.mean(axis=0)
    X = X - mean_X
    if dim > num_data:
        # PCA - compact trick user
        M = dot(X,X.T)
        e,EV = linalg.eigh(M)
        tmp = dot(X.T,EV).T
        V = tmp[::-1]
        S = sqrt(e)[::-1]
        for i in range(V.shape[1]):
            V[:,i] /= S
    else:
        U,S,V = linalg.svd(X)
        V = V[:num_data]
    return V,S,mean_X
