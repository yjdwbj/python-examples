#!/opt/stackless-279/bin/python
#-*- coding:utf-8-*-

import argparse
import os
import sys
import glob
import time
import threading
import mmap
import multiprocessing as mp
from multiprocessing import Process

from itertools import *

class A:
    pass

cdirs = ['t1','t2','t3','t4','t5']

logname =  ['err','state','recv','send','confirm','retransmit','lost']
#hdict= {'t1':'192.168.25.101','t2':'192.168.25.102','t3':'192.168.25.103','t4':'192.168.25.104','t5':'192.168.25.105','srv':'192.168.25.100'}

hdict = {'192.168.25.105': 't5', '192.168.25.104': 't4', '192.168.25.103': 't3', '192.168.25.102': 't2', '192.168.25.101': 't1', '192.168.25.100': 'srv'}

def make_argument_parser():
    parser = argpase.ArgumentParser(
            formatter_class = argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-f',action='store',dest="logfile",type=file,\
            help=u'输入出的日志文件')
#statlist = [os.stat(os.path.join(dirs[-1],n)) for n in os.listdir(dirs[-1])]  # get srv directory files stats

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
            tl = l.split(';')
            t = tl[1][7:21]
            mtype = tl[3].split('buf:')[1][28:32]
            ht = hdict[t]
            if not cmp('0006',mtype):
                """ app send to dev"""
                getattr(getattr(fwdwriteobj,ht),'app').write(l)
            elif not cmp(mtype,'0007'):
                """ dev send to app """
                getattr(getattr(fwdwriteobj,ht),'dev').write(l)


def mmap_findsomething(mm,crc32):
    if mm is None:
        return None
    mm.seek(0)
    while 1:
        ml = mm.readline()
        if ml == '':
            break
        if not cmp(ml[-8:],crc32):
            return ml
    return None

mmlist = ['send','recv','retransmit','confirm','lost']

def get_mmap(fname,lst):
    fd = open(fname,'r')
    lst.append(fd)
    return mmap.mmap(fd.fileno(),0,access=mmap.ACCESS_READ)

def get_filetolist(fname):
    biglist = []
    with open(fname,'r') as f:
        for l in f:
            biglist.append(l[-8:]) # 只取一个crc32的值做比对
    return biglist


def FindMatchInBigList(blist,crc32):
    try:
        n = blist.index(crc32) 
    except ValueError:
        return 0
    else:
        blist.pop(n) #清除找到的行，减少list体积
        return 1

def read_fwdlog(fname):
    """检测第一行"""
    """创建几个需要常读取的内存文件"""

    bname = os.path.split(fname)[-1]
    tdir = bname.split('_')[0]
    fdlist = []
    """ 这里通过查找上层目录，再找它的二级目录。只能处理t1.app --> t1.dev, 不能处理t1.app --> t3.dev"""
    """
    devmm = A()
    objhost = getattr(clientsdir,tdir)
    devobj = objhost.dev
    [setattr(devmm,"%s" % n,get_mmap(getattr(devobj,n),fdlist)) for n in mmlist] 
    appmm = A()
    #objhost = getattr(clientsdir,tdir)
    appobj = objhost.app
    [setattr(appmm,"%s" % n,get_mmap(getattr(appobj,n),fdlist)) for n in mmlist] 
    """
    devlist = A()
    objhost = getattr(clientsdir,tdir)
    devobj = objhost.dev 
    [setattr(devlist,'%s' % n,get_filetolist(getattr(devobj,n))) for n in mmlist]

    applist = A()
    appobj = objhost.app
    [setattr(applist,'%s' % n,get_filetolist(getattr(appobj,n))) for n in mmlist]

    
    base = os.path.splitext(os.path.split(fname)[1])[0]
    fwderrfd = open('%s_fwdout.log' % base,'w')

    fwderr = 0
    fwdok = 0
    refresh = time.time()+30
    startime = time.time()
    fwderrfd.write('start find match at time %.5f\n' % startime)
    with open(fname) as f:
        fdmm = mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
        while 1:
            l = fdmm.readline()
            if l == '':
                break
            if time.time() > refresh:
                refresh = time.time()+50
                fwdcount = fwdok + fwderr
                try:
                    print "%s,forward counter %d, forward success %d,forward error %d, error rate %.2f" % \
                            (fname,fwdcount,fwdok,fwderr,float(fwderr)/fwdcount)
                    fwderrfd.write("%.5f;%s,forward counter %d, forward success %d,forward error %d, error rate %.2f\n"\
                            % (time.time(),fname,fwdcount,fwdok,fwderr,float(fwderr)/fwdcount))
                    fwderrfd.flush()
                except ZeroDivisionError:
                    pass
            
            """下面的切片要根据实际文件调整"""
            feild = l.split(';')
            #src = feild[1][7:21]
            #dst = feild[2][8:22]
            buf = feild[3][5:]
            crc32 = buf[-8:]
            p = buf[28:32]
            isconfirm = buf[32:34]

            #srch = hdict[src]
            #dsth = hdict[dst]
            dfind = None
            sfind = None
            """
            if not cmp(p,'0007'):
                sfind = mmap_findsomething(devmm.send,crc32)
                if not sfind:
                    sfind = mmap_findsomething(devmm.retransmit,crc32)

                if not cmp(isconfirm,'02'):
                    dfind = mmap_findsomething(appmm.confirm,crc32)
                    if not dfind:
                        dfind = mmap_findsomething(appmm.lost,crc32)
                else:
                    dfind = mmap_findsomething(appmm.recv,crc32)
                    if not dfind:
                        dfind = mmap_findsomething(appmm.lost,crc32)

            #elif not cmp(p,'000702'):
            elif not cmp(p,'0006'):
                sfind = mmap_findsomething(appmm.send,crc32)
                if not sfind:
                    sfind = mmap_findsomething(appmm.retransmit,crc32)

                if not cmp(isconfirm,'02'):
                    dfind = mmap_findsomething(devmm.confirm,crc32)
                    if not dfind:
                        dfind = mmap_findsomething(devmm.lost,crc32)
                else:
                    dfind = mmap_findsomething(devmm.recv,crc32)
                    if not dfind:
                        dfind = mmap_findsomething(devmm.lost,crc32)
            """
            if not cmp(p,'0007'):
                sfind = FindMatchInBigList(devlist.send,crc32)
                if not sfind:
                    sfind = FindMatchInBigList(devlist.retransmit,crc32)

                if not cmp(isconfirm,'02'):
                    dfind = FindMatchInBigList(applist.confirm,crc32)
                    if not dfind:
                        dfind = FindMatchInBigList(applist.lost,crc32)
                        
                else:
                    dfind = FindMatchInBigList(applist.recv,crc32)
                    if not dfind:
                        dfind = FindMatchInBigList(applist.lost,crc32)

            elif not cmp(p,'0006'):
                sfind = FindMatchInBigList(applist.send,crc32)
                if not sfind:
                    sfind = FindMatchInBigList(applist.retransmit,crc32)

                if not cmp(isconfirm,'02'):
                    dfind = FindMatchInBigList(devlist.confirm,crc32)
                    if not dfind:
                        dfind = FindMatchInBigList(devlist.lost,crc32)

                else:
                    dfind = FindMatchInBigList(devlist.recv,crc32)
                    if not dfind:
                        dfind = FindMatchInBigList(devlist.lost,crc32)

                    
                
            if not dfind:
                fwderr +=1
                fwderrfd.write("%s, %s" % (l,'dst None\n'))
                """出错了，对方没有收到"""
            elif not sfind:
                fwderr +=1
                fwderrfd.write("%s, %s" % (l,'src None\n'))
            else:
                fwdok +=1
            #print "forward counter %d, forward success %d,forward error %d, error rate %.2f" % (fwdcount,fwdok,fwderr,float(fwderr)/fwdcount)
        fdmm.close()
    [fd.close() for fd in fdlist]
    fwdcount = fwdok + fwderr
    #fwderrfd.write('end find match at time %.5f\n' % time.time())
    fwderrfd.write("using time  %.5f;%s,forward counter %d, forward success %d,forward error %d, error rate %.2f\n"\
            % (time.time()- startime,fname,fwdcount,fwdok,fwderr,float(fwderr)/fwdcount))
    fwderrfd.close()



def join_logs(lname,mtype,hdir):
    """把 *err*.log *err*.log.1 合并成一个 err.log"""
    llist = glob.glob("%s/%s_dir/*%s*" % (hdir,mtype,lname))
    llist.sort(reverse=True)
    dstDir = os.path.dirname(llist[0])
    hn = os.path.join(curdir,dstDir)
    newname = '/'.join([hn,"%s.log" % lname])
    if os.path.exists(newname):
        return newname
    with open(newname,'w') as nf:
        for f in llist:
            with open(f,'r') as of:
                for ol in of:
                    nf.write(ol)

    return newname



def host_appdev(tdir):
    hn = os.path.join(curdir,tdir)
    h = A()
    h.app = A()
    h.dev = A()
    setattr(clientsdir,tdir,h)
    [setattr(h.app,n,join_logs(n,'app',tdir)) for n in logname ]
    [setattr(h.dev,n,join_logs(n,'dev',tdir)) for n in logname ]



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
    #print clientsdir.t1.app.__dict__
    #print clientsdir.t2.app.__dict__

    #threading.Thread(target=report_current).start()
    """先分割成小文件,确定是APP还是小机转发出来的
    """
    hosts = A()
    fwdlist =  glob.glob('srv/*fwd*')
    fwdlist.sort(reverse=True)
    fwdwriteobj = A()
    [setattr(fwdwriteobj,n,A()) for n in cdirs]
    #appfwdlist = ['srv/%s_app.log' % h for h in cdirs]
    #devfwdlist = ['srv/%s_dev.log' % h for h in cdirs]
    [setattr(getattr(fwdwriteobj,h),'app',open('srv/%s_app.log' % h,'w')) for h in cdirs ]
    [setattr(getattr(fwdwriteobj,h),'dev',open('srv/%s_dev.log' % h,'w')) for h in cdirs ]
    [split_fwdfiles(n) for n in fwdlist]
    [getattr(getattr(fwdwriteobj,h),'app').close() for h in cdirs]
    [getattr(getattr(fwdwriteobj,h),'dev').close() for h in cdirs]
    hostlist = glob.glob('srv/t[1-9]_*.log')
    #[v.close() for (k,v) in fwdict.iteritems()]
    """迭代读取srv上面的文件"""
    #pool = mp.Pool(processes=8)
    #pool.map(read_fwdlog,hostlist)
    #gevent.joinall(gevent.spawn([read_fwdlog(n) for n in hostlist]))
    plist = []#
    for n in hostlist:
        print n
        p = mp.Process(target=read_fwdlog,args=(n,))
        p.daemon = True
        p.start()
        plist.append(p)

    [n.join() for n in plist]

    # read t4 and t5
    #[read_fwdlog(n) for n in fwdlist]








