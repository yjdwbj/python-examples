#!/bin/python2
#coding=utf-8
import binascii
import random
import struct
import string
import threading
import time
import hmac
import hashlib
import uuid
import sys
import pickle
import select
import argparse
import os

from epoll_global import *
reload(sys)
sys.setdefaultencoding("utf-8")


def make_argument_parser():
    parser = argparse.ArgumentParser(
            formatter_class = argparse.ArgumentDefaultsHelpFormatter
            )
    parser.add_argument
    #parser.add_argument('-n',action='store',dest='vendor',type=str,help=u'厂商代码，4字节，少于自动补零，多于只取前面的，例如: -n test')
    parser.add_argument('-c',action='store',dest='count',type=int,help=u'产生UUID的数量，例如： -c 100')
    parser.add_argument('-f',action='store',dest='fname',type=str,help=u'文件名，可选')
    parser.add_argument('-r',action='store',dest='rname',type=file,help=u'读取文件UUID的数量，可选')
    parser.add_argument('--version',action='version',version=__version__)
    return parser



__version__ = '0.0.1'

if __name__ == '__main__':
    args = make_argument_parser().parse_args()
    #if not args.vendor or not args.count:

    if args.rname:
        n = 0
        while True:
            try:
                uid = pickle.load(args.rname)
                n+=1
            except EOFError:
                break
        print u'UUID 数量:%d' % n
        exit(0)



    if not args.count:
        print make_argument_parser().parse_args(['-h'])
        exit(-1)

    vendor = '0000'
    fname = args.fname if args.fname else vendor
#    if len(args.vendor) > 4:
#        vendor = args.vendor[:4]
#    elif len(args.vendor) < 4:
#        vendor = ''.join([args.vendor,'0000'[:4 - len(args.vendor)]])
#    else:
#        vendor = args.vendor
#

    uuidfd = open('%s.bin' % fname,'w')
    for i in xrange(args.count):
      uid = gen_random_jluuid(vendor)
      pickle.dump(uid,uuidfd)
    
    print u'文件保存到:',''.join([os.path.abspath('.'),os.path.sep ,fname,'.bin'])
    uuidfd.close()

