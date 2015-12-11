#!/opt/stackless-279/bin/python
#-*- coding:utf-8 -*-

from datetime import datetime
from sqlalchemy.exc import *
import sqlalchemy
from sqlalchemy.pool import NullPool
from sqlalchemy import Table,create_engine,Column,func,or_,not_,and_,ForeignKey,String,Integer,BigInteger,Date,MetaData,DateTime,Boolean,VARCHAR,sql,exists,literal,text
from sqlalchemy.dialects import postgresql as pgsql
from sqlalchemy.dialects.postgresql import BYTEA,UUID,TIMESTAMP
from sqlalchemy.sql.expression import insert,select,update,delete
from binascii import unhexlify,hexlify
import ConfigParser
from ConfigParser import NoOptionError
import sys
import json
from sys import exit

#SQLDriver='postgresql+psycopg2cffi://postgres:lcy123@192.168.25.105:5432/nath'

#SQLDriver="postgresql+psycopg2cffi://postgres:lcy123@nath.cavxfx5fkqgx.us-west-2.rds.amazonaws.com:5432"
DBNAME = "cmdb"
SYSTEMDB = None
def GetSqlDriver(fname):
    config = ConfigParser.SafeConfigParser()
    db = config.read(fname)
    if len(db) is 0:
        print "db config is not exists"
        sys.exit(0)
    db = config.sections()
    if 'db' not in 'db':
        print "config format error"
        exit(0)

    try:
        host = config.get('db','host')
    except NoOptionError:
        print "config format error,not found host items"
        exit(0)

    try:
        port = config.get('db','port')
    except NoOptionError:
        print "config format error,not found port items"
        exit(0)

    try:
        user = config.get('db','user')
    except NoOptionError:
        print "config format error,not found user   items"
        exit(0)

    try:
        password = config.get('db','password')
    except NoOptionError:
        print "config format error,not found password items"
        exit(0)
    global SYSTEMDB
    SYSTEMDB = "postgresql+psycopg2cffi://%s:%s@%s:%s/postgres" % (user,password,host,port)
        
    #return 'postgresql+psycopg2cffi://%s:%s@%s:%s/nath' % (user,password,host,port)
    return 'postgresql+psycopg2cffi://%s:%s@%s:%s/%s' % (user,password,host,port,DBNAME)


def GetConn(engine):
    #return engine.connect()
    try:
        conn = engine.connect()
    except OperationalError:
        print "Connection DataBase refused"
        exit(0)
    else:
        return conn



SQLDriver=GetSqlDriver("config.ini")

class PGError(Exception):
    def __init__(self,msg):
        self.msg = msg

def get_account_table():
    metadata = MetaData()
    account = Table('account',metadata,
            #Column('uuid',pgsql.UUID,primary_key=True),
            Column('uname',pgsql.VARCHAR(255),primary_key=True),
            Column('pwd',pgsql.BYTEA,nullable=False,default =''),
            Column('ftpwd',pgsql.VARCHAR(8),nullable=False,default =''),
            Column('is_active',pgsql.BOOLEAN,nullable=False,default=True),
            Column('reg_time',pgsql.TIMESTAMP,nullable=False,default='now()'),
            Column('reg_host',pgsql.VARCHAR(22),nullable=False,default='127.0.0.1')
            )
    return account



def get_vendor_table(): #记录厂商的名称
    metadata = MetaData()
    vtable = Table('vendor',metadata,
            Column('vname',pgsql.VARCHAR(8),nullable=False,primary_key=True,unique=True)
            )
    return vtable

def get_account_bind_table():
    metadata = MetaData()
    t = get_account_table()
    cmeta = t.tometadata(metadata)
    devtable = get_devices_table()
    cmeta = devtable.tometadata(metadata)
    table = Table('binds',metadata,
            Column('uname',pgsql.VARCHAR(255),ForeignKey('account.uname'),nullable=False),
            Column('devid',pgsql.BYTEA,ForeignKey('mirco_devices.devid'),nullable=False),
            Column('pwd',pgsql.BYTEA,default='',nullable=False),
            Column('bind_time',pgsql.TIMESTAMP,nullable=False,default='now()')
            )
    return table

def get_account_status_table():
    metadata = MetaData()
    t = get_account_table()
    cmeta = t.tometadata(metadata)
    table = Table('account_status',metadata,
            Column('uname',ForeignKey("account.uname"),primary_key=True,nullable=False),
            Column('is_login',pgsql.BOOLEAN,nullable=False,default=False),
            Column('last_login_time',pgsql.TIMESTAMP,default ='now()'),
            Column('last_logout_time',pgsql.TIMESTAMP,default='now()'),
            Column('chost',pgsql.VARCHAR(22),nullable=False,default='')
            )
    return table

def get_device_status_table():
    metadata = MetaData()
    devtable = get_devices_table()
    cmeta = devtable.tometadata(metadata)
    st = Table('devices_status',metadata,
            Column('devid',pgsql.BYTEA,ForeignKey('mirco_devices.devid'),primary_key=True,nullable=False),
            Column('last_login_time',pgsql.TIMESTAMP,nullable=False,default='now()'),
            Column('last_logout_time',pgsql.TIMESTAMP,nullable=False,default='now()'),
            Column('is_online',pgsql.BOOLEAN,nullable=False,default=False),
            Column('chost',pgsql.VARCHAR(22),nullable=False,default='')
            )

    return st



def get_devices_table():
    metadata = MetaData()
    vt = get_vendor_table()
    cmeta = vt.tometadata(metadata)
    mirco_devices = Table('mirco_devices',metadata,
            Column('vendor',ForeignKey('vendor.vname'),nullable=False),
            Column('devid',pgsql.BYTEA,primary_key=True,unique=True),
            Column('is_active',pgsql.BOOLEAN,nullable=False,default=True),
            Column('data',pgsql.BYTEA,nullable=False,default='')
            )
    return mirco_devices

class PostgresSQLEngine():
    def __init__(self):
        #self.engine = create_engine('postgresql+psycopg2cffi://postgres:postgres@127.0.0.1:5432/nath',pool_size=8192,max_overflow=4096,\
        #        poolclass=QueuePool)
        self.engine = create_engine(SQLDriver,poolclass=NullPool,client_encoding='utf-8')
        engine = create_engine(SYSTEMDB)
        conn = engine.connect()
        conn.execute('commit')
        try:
            conn.execute("create database %s" % DBNAME)
        except ProgrammingError:
            pass
        conn.close()
        self.check_boot_tables()


        
    """商厂表的相关操作"""

    def get_vendor_to_set(self):
        vt = get_vendor_table()
        ins = sql.select([vt.c.vname])
        conn = GetConn(self.engine)
        result = conn.execute(ins)
        n = result.fetchall()
        conn.close()
            #raise PGError('run query as %s occur err' % str(ins))
        mset= set()
        for row in n:
            mset.add(row['vname'])
        return mset


    def insert_vendor_table(self,vname):
        """
        INSERT INTO example_table
            (id, name)
        SELECT 1, 'John'
        WHERE
            NOT EXISTS (
                SELECT id FROM example_table WHERE id = 1
            );
        """
        
        vt = get_vendor_table()
        sel = sql.select([literal(vname)]).where(
                   ~exists([vt.c.vname]).where(vt.c.vname == literal(vname)))
        ins = vt.insert().from_select(['vname'], sel)
        return self.run_trans(ins)

    """ 用户表操作"""

    def update_account_table(self,uname,pwd,ftpwd,state,chost):
        at = get_account_table()
        ups = at.update().values(pwd = pwd,ftpwd = literal(ftpwd),is_active = state,reg_host=literal(chost)).where(at.c.uname == uname)
        return self.run_trans(ups)

    def insert_account_table(self,uname,pwd,ftpwd,chost):
        n = self.check_user_exist(uname)
        at = get_account_table()
        if not n:
            ins = at.insert().values(uname=literal(uname),pwd=str(pwd),ftpwd=literal(ftpwd),is_active=True,reg_host=literal(chost))
            conn = GetConn(self.engine)
            try:
                conn.execute(ins)
            except IntegrityError:
                conn.close()
                return
            conn.close()
        #sel = sql.select([literal(uname),literal(hexlify(pwd)),literal(ftpwd),True,literal(chost)]).where(
        #        ~exists([at.c.uname]).where(at.c.uname == literal(uname)))
        #ins = at.insert().from_select(['uname','pwd','ftpwd','is_active','reg_host'],sel)
            ast = get_account_status_table()
            ins = ast.insert().values(uname =literal(uname),chost = literal(chost))
            try:
                self.run_trans(ins)
            except IntegrityError:
                pass
            #trans.rollback()
            #raise PGError('run query as %s occur err' % str(ins))
            #raise

    def user_logout(self,uname):
        ast = get_account_status_table()
        ins = ast.update().values(last_logout_time = 'now()',is_login=False).where(ast.c.uname == literal(uname))
        return self.run_trans(ins)

    def user_login(self,uname,pwd,chost):
        at = get_account_table()
        ins = sql.select([at.c.uname,at.c.ftpwd]).where(and_(at.c.uname == literal(uname),at.c.pwd == str(pwd),at.c.is_active==True))
        n = None
        conn = GetConn(self.engine)
        n = conn.execute(ins)
        ftpwd = None
        if n != None:
            ftpwd = n.fetchone()
        #if n and n.fetchone():
            ast = get_account_status_table()
            ins = ast.update().values(last_login_time = 'now()',chost=literal(chost),is_login=True).where(ast.c.uname == literal(uname))
            self.run_trans(ins)
            
        conn.close()
        #trans.rollback()
        #raise PGError('run query as %s occur err' % str(ins))
        return ftpwd if ftpwd is None else ftpwd[1]

    def update_bind_table(self,uname,devid,pwd):
        bt = get_account_bind_table()
        ins = bt.update().values(pwd=pwd,bind_time = 'now()').where(bt.c.devid == str(devid))
        return self.run_trans(ins)

    def delete_bind_table(self,uname,devid):
        bt = get_account_bind_table()
        ins = bt.delete().where(and_(bt.c.devid == str(devid),bt.c.uname == uname))
        return self.run_trans(ins)

    def pull_bind_table(self,uname):
        bt = get_account_bind_table()
        ins  = sql.select([bt.c.devid,bt.c.pwd]).where(bt.c.uname == literal(uname))
        result = None
        conn = GetConn(self.engine)
        result = conn.execute(ins).fetchall()
        conn.close()
        mlist = []
        jdict = {}
        for row in result:
            jdict[row[0].encode('hex')] = row[1].encode('hex')

        data = json.dumps(jdict)
        #print "json data",data
        del mlist[:]
        del mlist
        return None if data == '{}' else data


    def insert_bind_table(self,uname,devid,pwd):
        bt = get_account_bind_table()
        #print "username,uuid",uname,devid.encode('hex')
        sel = sql.select([bt.c.devid,bt.c.uname]).where(and_(bt.c.devid == str(devid),bt.c.uname == uname))
        conn = GetConn(self.engine)
        result = conn.execute(sel)
        n = result.fetchone()
        if not n:
            ins = bt.insert().values(devid = str(devid),pwd=str(pwd),uname = uname)
            result = conn.execute(ins)
        conn.close()
        

    def check_user_exist(self,uname):
        at=get_account_table()
        s = sql.select([at.c.uname]).where(at.c.uname == literal(uname)).limit(1)
        conn = GetConn(self.engine)
        result = conn.execute(s)
        n = result.fetchone()
        conn.close()
        return n


    def query_appbind(self,uname,devid):
        bt = get_account_bind_table()
        sel = sql.select([bt.c.devid]).where(and_(bt.c.uname == uname,bt.c.devid == devid))
        n = None
        conn = GetConn(self.engine)
        n = conn.execute(sel)
        res = n.fetchone()
        conn.close()
        return res


    """ 小机表的操作"""



    """ 小机表的操作"""
    def devtable_logout(self,devid):
        #dt = get_devices_table()
        dt = get_device_status_table()
        ins = dt.update().values(last_logout_time='now()',is_online=False).where(dt.c.devid == str(devid))
        return self.run_trans(ins)

    def check_device_exist(self,devid):
        dt = get_devices_table()
        s = sql.select([dt.c.devid]).where(dt.c.devid == str(devid)).limit(1)
        n = None
        conn = GetConn(self.engine)
        result = conn.execute(s)
        n = result.fetchone()
        conn.close()

        return n

    def insert_devtable(self,vname,devid,chost,data):
        dt = get_devices_table()
        #n = self.check_device_exist(devid)
        #if not n:
            #sel = sql.select([literal(vname),literal(devid),True,literal(data)]).where(~exists([dt.c.devid]).where(dt.c.devid == literal(devid)))
            #ins = dt.insert().from_select(['vendor','devid','is_active','data'],sel)
        ins = dt.insert().values(devid=str(devid),vendor=vname,is_active=True,data=data)
        conn = GetConn(self.engine)
        try:
            conn.execute(ins)
        except IntegrityError:
            pass
        conn.close()
            
        dst = get_device_status_table()
        #sel = sql.select([literal(devid),text('CURRENT_TIMESTAMP'),True,literal(chost)]).where(~exists([dt.c.devid]).where(dt.c.devid == literal(devid)))
        #ins = dst.insert().from_select(['devid','last_login_time','is_online','chost'],sel)
        stats = dst.insert().values(devid=devid,last_login_time =literal('now()'),is_online = True,chost = literal(chost))
        conn = GetConn(self.engine)
        try:
            conn.execute(stats)
        except IntegrityError:
            stats = dst.update().values(last_login_time = literal('now()'),is_online = True).where(dst.c.devid == str(devid))
            conn.execute(stats)
        conn.close()



    def run_trans(self,ins):
        conn = GetConn(self.engine)
        conn.execute(ins)
        conn.close()


    #@staticmethod
    def check_boot_tables(self):
        conn = GetConn(self.engine)

        vtable = get_vendor_table()
        if not vtable.exists(self.engine):
            vtable.create(self.engine)

        atable = get_account_table()
        if not atable.exists(self.engine):
            atable.create(self.engine)

        stable = get_account_status_table()
        if not stable.exists(self.engine):
            stable.create(self.engine)

        devtable = get_devices_table()
        if not devtable.exists(self.engine):
            devtable.create(self.engine)


        abt = get_account_bind_table()
        if not abt.exists(self.engine):
            abt.create(self.engine)

        dst = get_device_status_table()
        if not dst.exists(self.engine):
            dst.create(self.engine)
        conn.close()

