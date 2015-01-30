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

from epoll_global import *


def make_argument_parser():
    parser = argparse.ArgumentParser(
            formatter_class = argparse.ArgumentDefaultsHelpFormatter
            )
    parser.add_argument
    parser.add_argument('-n',action='store',dest='vendor',type=str,help=u'厂商代码，4字节，少于自动补零，多于只取前面的，例如: -n test')
    parser.add_argument('-c',action='store',dest='count',type=int,help=u'产生UUID的数量，例如： -c 100')
    parser.add_argument('--version',action='version',version=__version__)
    return parser



__version__ = '0.0.1'

if __name__ == '__main__':
    args = make_argument_parser().parse_args()
    if not args.vendor or not args.count:
        print make_argument_parser().parse_args(['-h'])
        exit(-1)

    uuidfd = open(''.join([args.vendor,'.bin']),'w')
    for i in xrange(args.count):
      uid = gen_random_jluuid(args.vendor)
      pickle.dump(uid,uuidfd)
    uuidfd.close()

