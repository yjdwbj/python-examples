#!bin/python 
#-*- coding:utf-8 -*-

import sys,os
import ConfigParser
import json

class SectionFM():
    def __init__(self,pname):
        name = pname
        items = {}
    

#def ListToDict(d,n,cf,path):
def ListToDict(d,n,cf):
    #d[n] = dict(cf.items(n))
    #d[n] = [(k,v,path+'/'+hashlib.sha256(k).hexdigest()+'.png') for (k,v) in cf.items(n)]
    d[n] = cf.items(n)


def ReadIni(fname):
    cf = ConfigParser.ConfigParser()
    cf.read(fname)

    sections = set(cf.sections())
    mdict = {}
    [ListToDict(mdict,n,cf) for n in sections]
    with open('app/static/json/fm_address.json','w') as f:
        f.write(json.dumps(mdict))
        
    return mdict


    
