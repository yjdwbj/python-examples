#!/opt/stackless-279/bin/python
#-*- coding:utf-8-*-

import argparse
import os
import sys
import glob
import time
import threading
import mmap

from itertools import *

class A:
    pass

cdirs = ['t1','t2','t3','t4','t5']

logname =  ['err','stat','recv','send','confirm','retransmit']
#hdict= {'t1':'192.168.25.101','t2':'192.168.25.102','t3':'192.168.25.103','t4':'192.168.25.104','t5':'192.168.25.105','srv':'192.168.25.100'}

hdict = {'192.168.25.105': 't5', '192.168.25.104': 't4', '192.168.25.103': 't3', '192.168.25.102': 't2', '192.168.25.101': 't1', '192.168.25.100': 'srv'}


def make_argument_parser():
    parser = argpase.ArgumentParser(
            formatter_class = argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-f',action='store',dest="logfile",type=file,\
            help=u'输入出的日志文件')
    return parser


#statlist = [os.stat(os.path.join(dirs[-1],n)) for n in os.listdir(dirs[-1])]  # get srv directory files stats

def read_logs(flist,send):
    ret = 0
    for n in flist:
        with open(n) as f:
            for l in f:
                try:
                    l.index(send)
                except ValueError:
                    continue
                else:
                    return l

    return None

def report_current():
    global fwdcount,fwdok,fwderr
    while 1:
        try:
            print "forward counter %d, forward success %d,forward error %d, error rate %.2f" % (fwdcount,fwdok,fwderr,float(fwderr)/fwdcount)
        except ZeroDivisionError:
            pass
        time.sleep(30)

def split_fwdfiles(fname):
    with open(fname) as f:
        for l in f:
            t = l.split('|')[1][7:21]
            mtype = l.split('buf:')[1][28:32]
            ht = hdict[t]
            if mtype == '0006': 
                """ app send to dev"""
                getattr(getattr(fwdwriteobj,ht),'app').write(l)
            else:
                """ dev send to app """
                getattr(getattr(fwdwriteobj,ht),'dev').write(l)
            #fwdict[hdict[t]].write(l)

def get_host_peer(obj,host,mtype):
    return getattr(getattr(obj,host),mtype)


def mmap_findsomething(mmobj,buf):
    mmobj.seek(0)
    with mmobj as mm:
        for ml in mm:
            try:
                ml.index(buf)
            except ValueError:
                continue
            else:
                return ml

    return None

def read_fwdlog(fname):
    """检测第一行"""
    td = open(fname,'r')
    l = td.readline()
    td.close()
    srch = hdict[l.split('src:')[1].strip('[(\'')[:14]]
    dsth = hdict[l.split('dst:')[1].strip('[(\'')[:14]]
    """创建几个需要常读取的内存文件"""
    srcmmap1 = None
    srcmmap2 = None
    dstmmap1 = None
    dstmmap2 = None
    if fname.find('app'):
        objsrc = getattr(clientsdir,srch)
        srcmmap1 = mmap.mmap(open(objsrc.dev.send,'r').fileno(),0,access=mmap.ACCESS_READ)
        srcmmap2 = mmap.mmap(open(objsrc.dev.retransmit,'r').fileno(),0,access=mmap.ACCESS_READ)
        objdst = getattr(clientsdir,dsth)
        dstmmap1 = mmap.mmap(open(objdst.dev.recv,'r').fileno(),0,access=mmap.ACCESS_READ)
        dstmmap2 = mmap.mmap(open(objdst.dev.confirm,'r').fileno(),0,access=mmap.ACCESS_READ)
    elif fname.find('dev'):
        objsrc = getattr(clientsdir,srch)
        srcmmap1 = mmap.mmap(open(objsrc.app.send,'r').fileno(),0,access=mmap.ACCESS_READ)
        srcmmap2 = mmap.mmap(open(objsrc.app.retransmit,'r').fileno(),0,access=mmap.ACCESS_READ)
        objdst = getattr(clientsdir,dsth)
        dstmmap1 = mmap.mmap(open(objdst.app.recv,'r').fileno(),0,access=mmap.ACCESS_READ)
        dstmmap2 = mmap.mmap(open(objdst.app.confirm,'r').fileno(),0,access=mmap.ACCESS_READ)

    global fwdcount,fwderr,fwdok
    with open(fname) as f:
        for l in f:
            """下面的切片要根据实际文件调整"""
            feild = l.split(']')
            src = feild[0].split('[')[1].strip('()')
            dst = feild[1].split('[')[1].strip('()')
            buf = feild[2].split(':')[1].strip('\n')
            p = buf[32:34]

            srch = hdict[l.split('src:')[1].strip('[(\'')[:14]]
            dsth = hdict[l.split('dst:')[1].strip('[(\'')[:14]]
            """找源地址"""
            sfind = mmap_findsomething(srcmmap1,buf)
            if sfind is None:
                sfind = mmap_findsomething(srcmmap2,buf)
                    
            dfind = ''
            if p == '03':
                """recv"""
                dfind = mmap_findsomething(dstmmap1,buf)
            else:
                """confirm"""
                dfind = mmap_findsomething(dstmmap2,buf)

                
            fwdcount +=1
            if dfind is None:
                fwderr +=1
                fwderrfd.write("%s, %s" % (l,'dst None\n'))
                """出错了，对方没有收到"""
            elif sfind is None:
                fwderr +=1
                fwderrfd.write("%s, %s" % (l,'src None\n'))
    srcmmap1.close()
    srcmmap2.close()
    dstmmap1.close()
    dstmmap2.close()




def host_appdev(tdir):
    hn = os.path.join(curdir,tdir)
    print hn
    h = A()
    h.app = A()
    h.dev = A()
    setattr(clientsdir,tdir,h)
    [setattr(h.app,n,f) for n in logname for f in glob.glob("%s/app_dir/*%s*" % (hn,n))]
    [setattr(h.dev,n,f) for n in logname for f in glob.glob("%s/dev_dir/*%s*" % (hn,n))]




"""
通过转发文件来分析两端的正确性
"""
clientsdir = A()
if __name__ == "__main__":
    curdir = os.getcwd()
    ldir = os.listdir(curdir)
    fwdcount  = 0
    fwdok = 0
    fwderr = 0
    
    try:
        [ldir.index(n) for n in cdirs]
    except ValueError:
        print n,"not exists,Exiting"
        sys.exit(1)

    [host_appdev(n) for n in cdirs]
    #[get_logsname(clientsdir,n)for n in cdirs] # 命名空间而以 clientsdir.t1.app.stat clientsdir.t2.dev.stat clientsdir.t1.err
    print clientsdir.t1.app.__dict__
    print clientsdir.t2.app.__dict__

    #fwderrfd = open('fwderrlogs.log','w+')
    threading.Thread(target=report_current).start()
    """先分割成小文件,确定是APP还是小机转发出来的
    hosts = A()
    fwdlist =  glob.glob('srv/*fwd*')
    fwdlist.sort(reverse=True)
    fwdwriteobj = A()
    [setattr(fwdwriteobj,n,A()) for n in cdirs]
    [setattr(getattr(fwdwriteobj,h),'app',open('srv/%s_app.log' % h,'w')) for h in cdirs]
    [setattr(getattr(fwdwriteobj,h),'dev',open('srv/%s_dev.log' % h,'w')) for h in cdirs]
    [split_fwdfiles(n) for n in fwdlist]
    #[v.close() for (k,v) in fwdict.iteritems()]
    [getattr(getattr(fwdwriteobj,h),'app').close() for h in cdirs]
    [getattr(getattr(fwdwriteobj,h),'dev').close() for h in cdirs]
    """
    hostlist = glob.glob('srv/t[1-9]_*.log')
    [read_fwdlog(n) for n in hostlist]


    # read t4 and t5
    #[read_fwdlog(n) for n in fwdlist]
    print "forward counter %d, forward success %d,forward error %d" % (fwdcount,fwdok,fwderr)
    #fwderrfd.close()








