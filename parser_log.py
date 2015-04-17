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
            mtype = tl[3].split('buf:')[1][28:34]
            """
            t = l.split('|')[1][7:21]
            mtype = l.split('buf:')[1][28:32]
            """
            ht = hdict[t]
            if mtype == '000603': 
                """ app send to dev"""
                getattr(getattr(fwdwriteobj,ht),'app').write(l)
            elif mtype == '000602':
                getattr(getattr(fwdwriteobj,ht),'dev').write(l)
                """ dev confirm to app"""
            elif mtype == '000703':
                """ dev send to app """
                getattr(getattr(fwdwriteobj,ht),'dev').write(l)
            elif mtype == '000702':
                """ app confirm to dev """
                getattr(getattr(fwdwriteobj,ht),'app').write(l)
            #fwdict[hdict[t]].write(l)


def mmap_findsomething(mm,buf):
    if mm is None:
        return None
    mm.seek(0)
    while 1:
        ml = mm.readline()
        if ml == '':
            break
        try:
            ml.index(buf)
        except ValueError:
            continue
        else:
            return ml
    return None

mmlist = ['send','recv','retransmit','confirm','lost']

def get_mmap(fname):
    fd = open(fname,'r')
    return mmap.mmap(fd.fileno(),0,access=mmap.ACCESS_READ)

def read_fwdlog(fname):
    """检测第一行"""
    td = open(fname,'r')
    l = td.readline()
    td.close()
    feild = l.split(';')
    srch = hdict[feild[1][7:21]]
    dsth = hdict[feild[2][8:22]]
    #srch = hdict[l.split('src:')[1].strip('[(\'')[:14]]
    #dsth = hdict[l.split('dst:')[1].strip('[(\'')[:14]]
    """创建几个需要常读取的内存文件"""
    devmm = A()
    objhost = getattr(clientsdir,srch)
    devobj = objhost.dev
    [setattr(devmm,"%smmap" % n,get_mmap(getattr(devobj,n))) for n in mmlist] 
    appmm = A()
    objhost = getattr(clientsdir,srch)
    appobj = objhost.app
    [setattr(appmm,"%smmap" % n,get_mmap(getattr(appobj,n))) for n in mmlist] 
    
    
    
    srcmmap2 = None
    dstmmap1 = None
    dstmmap2 = None
    dstmmap3 = None
    fdlist = []
    time.sleep(1)
    
    if fname.find('app'):
        """ APP 的转发日志"""
        objsrc = getattr(clientsdir,srch)
        if os.stat(objsrc.app.send).st_size > 0:
            fd = open(objsrc.app.send,'r')
            print  "app file for src send mmap file",fd.name
            fdlist.append(fd)
            srcmmap1 = mmap.mmap(fd.fileno(),0,access=mmap.ACCESS_READ)
        if os.stat(objsrc.app.retransmit).st_size >0:
            fd = open(objsrc.app.retransmit,'r')
            fdlist.append(fd)
            srcmmap2 = mmap.mmap(fd.fileno(),0,access=mmap.ACCESS_READ)

        objdst = getattr(clientsdir,dsth)
        if os.stat(objdst.dev.recv).st_size >0:
            fd = open(objdst.dev.recv,'r')
            print  "app file for dst recv  mmap file",fd.name
            fdlist.append(fd)
            dstmmap1 = mmap.mmap(fd.fileno(),0,access=mmap.ACCESS_READ)

        if os.stat(objdst.dev.confirm).st_size >0:
            fd = open(objdst.dev.confirm,'r')
            fdlist.append(fd)
            dstmmap2 = mmap.mmap(fd.fileno(),0,access=mmap.ACCESS_READ)

        if os.stat(objdst.dev.lost).st_size >0:
            fd = open(objdst.dev.lost,'r')
            fdlist.append(fd)
            dstmmap3 = mmap.mmap(fd.fileno(),0,access=mmap.ACCESS_READ)

    elif fname.find('dev'):
        objsrc = getattr(clientsdir,srch)
        if os.stat(objsrc.dev.send).st_size > 0:
            fd = open(objsrc.dev.send,'r')
            print  "dev file for src mmap file",fd.name
            fdlist.append(fd)
            srcmmap1 = mmap.mmap(fd.fileno(),0,access=mmap.ACCESS_READ)
        if os.stat(objsrc.dev.retransmit).st_size >0:
            fd = open(objsrc.dev.retransmit,'r')
            fdlist.append(fd)
            srcmmap2 = mmap.mmap(fd.fileno(),0,access=mmap.ACCESS_READ)

        objdst = getattr(clientsdir,dsth)
        if os.stat(objdst.app.recv).st_size >0:
            fd = open(objdst.app.recv,'r')
            print  "dev file for dst recv  mmap file",fd.name
            fdlist.append(fd)
            dstmmap1 = mmap.mmap(fd.fileno(),0,access=mmap.ACCESS_READ)
        if os.stat(objdst.app.confirm).st_size >0:
            fd = open(objdst.app.confirm,'r')
            fdlist.append(fd)
            dstmmap2 = mmap.mmap(fd.fileno(),0,access=mmap.ACCESS_READ)

        if os.stat(objdst.app.lost).st_size >0:
            fd = open(objdst.app.lost,'r')
            fdlist.append(fd)
            dstmmap3 = mmap.mmap(fd.fileno(),0,access=mmap.ACCESS_READ)

    
    base = os.path.splitext(os.path.split(fname)[1])[0]
    fwderrfd = open('%s_fwderr.log' % base,'w')

    fwderr = 0
    fwdok = 0
    refresh = time.time()+30
    with open(fname) as f:
        for l in f:
            if time.time() > refresh:
                refresh = time.time()+50
                fwdcount = fwdok + fwderr
                try:
                    print "%s,forward counter %d, forward success %d,forward error %d, error rate %.2f" % \
                            (fname,fwdcount,fwdok,fwderr,float(fwderr)/fwdcount)
                except ZeroDivisionError:
                    pass
            
            """下面的切片要根据实际文件调整"""
            feild = l.split(';')
            src = feild[1][7:21]
            dst = feild[2][8:22]
            buf = feild[3][5:]
            p = buf[32:34]

            srch = hdict[src]
            dsth = hdict[dst]

                    
            dfind = None
            if p == '03':
                """找源地址"""
                sfind = mmap_findsomething(srcmmap1,buf)
                if sfind is None:
                    sfind = mmap_findsomething(srcmmap2,buf)
                dfind = mmap_findsomething(dstmmap1,buf)
            else:
                dfind = mmap_findsomething(dstmmap2,buf)
                if dfind is None and dstmmap3:
                    dfind = mmap_findsomething(dstmmap3,buf)
                
            if dfind is None:
                fwderr +=1
                fwderrfd.write("%s, %s" % (l,'dst None\n'))
                """出错了，对方没有收到"""
            else:
                fwdok +=1
            #print "forward counter %d, forward success %d,forward error %d, error rate %.2f" % (fwdcount,fwdok,fwderr,float(fwderr)/fwdcount)
    srcmmap1.close()
    srcmmap2.close()
    dstmmap1.close()
    dstmmap2.close()
    dstmmap3.close()
    [fd.close() for fd in fdlist]
    fwdcount = fwdok + fwderr
    fwderrfd.write("%s,forward counter %d, forward success %d,forward error %d, error rate %.2f"\
            % (fname,fwdcount,fwdok,fwderr,float(fwderr)/fwdcount))
    fwderrfd.close()

def process_find_peer(tpair):
    m0 = tpair[0]
    m1 = tpair[1]
    buf = tpair[2]
    fstr = None
    if m0:
        fstr = mmap_findsomething(m0,buf)
    if fstr is None and m1:
        fstr = mmap_findsomething(m1,buf)
    return fstr



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
    print "forward counter %d, forward success %d,forward error %d" % (fwdcount,fwdok,fwderr)








