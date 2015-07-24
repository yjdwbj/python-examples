#!/usr/bin/python 

import json
import urllib2
import time
import os
import shutil

hostwww  = "www.radio.cn"
hostbk   = "bk2.radio.cn"
Referer  = "http://www.radio.cn"

new_fmlist = "radio_fm_list.txt"
old_fmlist = "radio_fm_list.txtold"

allfmjson = "http://bk2.radio.cn/mms4/videoPlay/pcGetChannels.jspa?area=-1&type=-1"
callback = "jQuery183021457383082195502_1437729952489"
tp = "&_=1437731702453"
allfmjson = "http://bk2.radio.cn/mms4/videoPlay/pcGetChannels.jspa?area=0&type=0&callback=%s%s" % (callback,tp)
getfmjson = "http://bk2.radio.cn/mms4/videoPlay/getChannelPlayInfoJson.jspa?channelId={0}&terminalType=PC&location=http%3A//www.radio.cn/&callback=jQuery183021457383082195502_1437729952486&_=1437735133205"



headers = { "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",\
            "User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:37.0) Gecko/20100101 Firefox/37.0",\
            "Accept-Encoding": "gzip,deflate",\
            "Accept-Language": "en-US,en;q=0.8,zh-CN;q=0.6,zh;q=0.4",\
            "Connection": "keep-alive",\
            "Cache-Control": "max-age=0"\
            }




def refresh_json():
    headers["Host"] = hostbk
    headers["Referer"] = Referer
    Req = urllib2.Request(allfmjson,headers = headers)
    Res = urllib2.urlopen(Req)
    jsondata = Res.read()
    jsondata = jsondata[len(callback):][1:-1]
    with open('radio_cn_json_%d.json' % time.time(),'w') as f:
        f.write(jsondata)

 
def read_json_file(fname):
    data = None
    with open(fname,'r') as f:
        data = json.load(f)
    return data

def read_fm_json(channelid):
    headers["Host"] = hostbk
    headers["Referer"] = Referer
    Req = urllib2.Request(getfmjson.format(channelid) ,headers = headers)
    Res = urllib2.urlopen(Req)
    fmjson = Res.read()
    fmjson = fmjson[fmjson.index('(')+1:-1]
    return fmjson
    
def make_ini_line(dstr):
    print dstr.split(',')
    nd = eval(dstr)
    print nd
    return str(nd["channelName"] + "="+ nd["streams"][0]["url"])


jsondata = read_json_file("radion_cn_json_1437737412.json")
fmlist = []
for it in jsondata:
     fmlist.append(make_ini_line( read_fm_json(it["channelId"])))

#curabs = os.path.abspath('.')

if os.path.isfile(new_fmlist):
    shutil.move(new_fmlist,old_fmlist)
with open(new_fmlist,'w') as f:
    [f.write(l+'\n') for l in fmlist]
#
print "create new_fmlist OK"






