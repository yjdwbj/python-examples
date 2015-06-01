#!/opt/stackless-279/bin/python

from datetime import datetime
from sqlalchemy.exc import *
from sqlalchemy import Table,create_engine,Column,func,or_,not_,and_,ForeignKey,String,Integer,BigInteger,Date,MetaData,DateTime,Boolean,VARCHAR,sql,exists,literal,text
from sqlalchemy.dialects import postgresql as pgsql
from sqlalchemy.dialects.postgresql import BYTEA,UUID,TIMESTAMP
from sqlalchemy.pool import QueuePool
from sqlalchemy.sql.expression import insert,select,update,delete
from binascii import unhexlify,hexlify

SQLDriver='postgresql+psycopg2cffi://postgres:lcy123@192.168.25.105:5432/nath'

#SQLDriver="postgresql+psycopg2cffi://postgres:lcy123@nath.cavxfx5fkqgx.us-west-2.rds.amazonaws.com:5432"

class PGError(Exception):
    def __init__(self,msg):
        self.msg = msg

def get_account_table():
    metadata = MetaData()
    account = Table('account',metadata,
            #Column('uuid',pgsql.UUID,primary_key=True),
            Column('uname',pgsql.VARCHAR(255),primary_key=True),
            Column('pwd',pgsql.BYTEA,nullable=False,default =''),
            Column('is_active',pgsql.BOOLEAN,nullable=False,default=True),
            Column('reg_time',pgsql.TIME,nullable=False,default='now()'),
            Column('reg_host',pgsql.VARCHAR(22),nullable=False,default='127.0.0.1')
            )
    return account

def get_vendor_table(): #记录厂商的名称
    metadata = MetaData()
    vtable = Table('vendor',metadata,
            Column('vname',pgsql.VARCHAR(8),nullable=False,primary_key=True,unique=True)
            )
    return vtable

def get_account_bind_table(name):
    metadata = MetaData()
    table = Table(name,metadata,
            Column('devid',pgsql.VARCHAR(48),nullable=False,primary_key=True),
            Column('pwd',pgsql.BYTEA,default='',nullable=False),
            Column('bind_time',pgsql.TIME,nullable=False,default='now()')
            )
    return table

def get_account_status_table():
    metadata = MetaData()
    t = get_account_table()
    cmeta = t.tometadata(metadata)
    table = Table('account_status',metadata,
            Column('uname',pgsql.VARCHAR(255),ForeignKey("account.uname")),
            Column('is_login',pgsql.BOOLEAN,nullable=False,default=False),
            Column('last_login_time',pgsql.TIME,default ='now()'),
            Column('last_logout_time',pgsql.TIME,default='now()'),
            Column('chost',pgsql.VARCHAR(22),nullable=False,default='')
            )
    return table


def get_devices_table(vendor_name):
    metadata = MetaData()
    mirco_devices = Table(vendor_name,metadata,
            Column('devid',pgsql.UUID,primary_key=True,unique=True),
            Column('is_active',pgsql.BOOLEAN,nullable=False,default=True),
            Column('last_login_time',pgsql.TIMESTAMP,nullable=False,default='now()'),
            Column('last_logout_time',pgsql.TIMESTAMP,nullable=False,default='now()'),
            Column('is_online',pgsql.BOOLEAN,nullable=False,default=False),
            Column('chost',pgsql.VARCHAR(22),nullable=False,default=''),
            Column('data',pgsql.BYTEA,nullable=False,default='')
            )
    return mirco_devices

class PostgresSQLEngine():
    def __init__(self):
        #self.engine = create_engine('postgresql+psycopg2cffi://postgres:postgres@127.0.0.1:5432/nath',pool_size=8192,max_overflow=4096,\
        #        poolclass=QueuePool)
        self.engine = create_engine(SQLDriver,pool_size=8192,max_overflow=4096)

    def check_table(self,table):
        return table.exists(self.engine)

    def get_engine(self):
        return self.engine

    def get_dbconn(self):
        return self.get_engine().connect()

    def nexecute(self,stmt): #不做返回的查询
        self.get_dbconn().execute(stmt)
    
    def execute(self,stmt):
        result = self.get_dbconn().execute(stmt)
        res = []
        try:
            for row in result:
                res.append(str(row))
        except ResourceClosedError:
            res = []
        return res
        #return self.get_dbconn().execute(stmt)
        

    def rawselect(self,stmt):
        self.get_engine().execute("select %s;" % stmt);

    def create_table(self,sql_txt):
        self.engine.connect().execute(sql_txt)
        
    """商厂表的相关操作"""

    def get_vendor_to_set(self):
        vt = get_vendor_table()
        ins = sql.select([vt.c.vname])
        conn = self.engine.connect()
        trans = conn.begin()
        result = None
        try:
            result = conn.execute(ins).fetchall()
            trans.commit()
        except:
            trans.rollback()
            raise PGError('run query as %s occur err' % str(ins))
        mset= set()
        for row in result:
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

    def insert_account_table(self,uname,pwd,chost):
        at = get_account_table()
        sel = sql.select([literal(uname),literal(hexlify(pwd)),True,at.c.reg_time,literal(chost)]).where(
                ~exists([at.c.uname]).where(at.c.uname == literal(uname)))
        ins = at.insert().from_select(['uname','pwd','is_active','reg_time','reg_host'],sel)
        conn = self.get_dbconn()
        trans = conn.begin()
        conn.execute(ins)
        trans.commit()
        ast = get_account_status_table()
        ins = ast.insert().values(uname =literal(uname),chost = literal(chost))
        self.run_trans(ins)
            #trans.rollback()
            #raise PGError('run query as %s occur err' % str(ins))
            #raise

    def user_logout(self,uname):
        ast = get_account_status_table()
        ins = ast.update().values(last_logout_time = 'now()',is_login=False).where(ast.c.uname == literal(uname))
        return self.run_trans(ins)

    def user_login(self,uname,pwd,chost):
        at = get_account_table()
        ins = sql.select([at.c.uname]).where(and_(at.c.uname == literal(uname),at.c.pwd == literal(hexlify(pwd)),at.c.is_active==True))
        conn = self.get_dbconn()
        trans = conn.begin()
        n = None
        n = conn.execute(ins).first()
        trans.commit()
        if n:
            ast = get_account_status_table()
            ins = ast.update().values(last_login_time = 'now()',chost=literal(chost),is_login=True).where(ast.c.uname == literal(uname))
            self.run_trans(ins)
        #trans.rollback()
        #raise PGError('run query as %s occur err' % str(ins))

        return n
    def update_bind_table(self,uname,devid,pwd):
        bt = get_account_bind_table(uname)
        ins = bt.update().values(pwd=pwd,bind_time = 'now()').where(bt.c.devid == literal(devid))
        return self.run_trans(ins)

    def delete_bind_table(self,uname,devid):
        bt = get_account_bind_table(uname)
        ins = bt.delete().where(bt.c.devid == devid)
        return self.run_trans(ins)

    def pull_bind_table(self,uname):
        bt = get_account_bind_table(uname)
        ins  = sql.select([bt.c.devid,bt.c.pwd])
        conn = self.get_dbconn()
        trans = conn.begin()
        result = None
        try:
            result = conn.execute(ins).fetchall()
            trans.commit()
        except:
            trans.rollback()
            raise PGError('run query as %s occur err' % str(ins))

        mlist = []
        for row in result:
            mlist.extend(list(row))

        data = ''.join(mlist)
        del mlist[:]
        del mlist
        return data


    def insert_bind_table(self,uname,devid,pwd):
        bt = get_account_bind_table(uname)
        sel = sql.select([literal(devid),literal(pwd)]).where(~exists([bt.c.devid]).where(bt.c.devid == literal(devid)))
        ins = bt.insert().from_select(['devid','pwd'],sel)
        return self.run_trans(ins)

    def check_user_exist(self,uname):
        at=get_account_table()
        s = sql.select([at.c.uname]).where(at.c.uname == literal(uname)).limit(1)
        conn = self.get_dbconn()
        trans = conn.begin()
        n = None
        n = conn.execute(s).first()
        trans.commit()
            #trans.rollback()
            #raise PGError('run query as %s occur err' % str(s))
        return n

    """ 小机表的操作"""
    def devtable_logout(self,vname,devid):
        dt = get_devices_table(vname)
        ins = dt.update().values(last_logout_time='now()',is_online=False).where(dt.c.devid == literal(devid))
        return self.run_trans(ins)

    def insert_devtable(self,vname,devid,chost,data):
        dt = get_devices_table(vname)
        conn = self.get_dbconn()
        trans = conn.begin()
        sel = sql.select([literal(devid),True,text('CURRENT_TIMESTAMP'),text('CURRENT_TIMESTAMP'),True,literal(chost),literal(data)]).where(~exists([dt.c.devid]).where(dt.c.devid == literal(devid)))
        ins = dt.insert().from_select(['devid','is_active','last_login_time','last_logout_time','is_online','chost','data'],sel)
        return self.run_trans(ins)

    @staticmethod
    def select(sql_txt):
        engine = create_engine(SQLDriver)
        #engine = create_engine('postgresql+psycopg2cffi://postgres:lcy123@127.0.0.1:5432/nath')
        conn = engine.connect()
        result = conn.execute(sql_txt)
        res = []
        try:
            for row in result:
                res.append(str(row))
        except ResourceClosedError:
            res = []
        conn.close()
        return res



    def run_trans(self,ins):
        conn = self.get_dbconn()
        trans = conn.begin()
        try:
            conn.execute(ins)
            trans.commit()
        except:
            trans.rollback()
            #raise PGError('run query as %s occur err' % str(ins))
            raise


    @staticmethod
    def check_boot_tables():
        engine = create_engine(SQLDriver)
        conn = engine.connect()
        atable = get_account_table()
        if not atable.exists(engine):
            atable.create(engine)
            conn.execute("""
            CREATE OR REPLACE FUNCTION add_bindtable() RETURNS TRIGGER AS $BODY$
            BEGIN
            EXECUTE format('
            CREATE TABLE IF NOT EXISTS "'||NEW.uname||'"  (
              devid VARCHAR(48) NOT NULL PRIMARY KEY,
              pwd BYTEA ,
              bind_time timestamp with time zone DEFAULT now()
              );');
            RETURN NEW;
            END;
            $BODY$ LANGUAGE plpgsql;

            
            DROP TRIGGER IF EXISTS add_bind ON account;
            CREATE TRIGGER add_bind BEFORE INSERT OR UPDATE ON account FOR EACH ROW EXECUTE PROCEDURE add_bindtable();
---           CREATE OR REPLACE FUNCTION insert_account_status() RETURNS TRIGGER as ---
---               $$---
---           BEGIN---
---           EXECUTE format('---
---           INSERT into account_status (uname,chost) VALUES(quote_ident('||NEW.uname||'),quote_ident('||NEW.chost||'));');---
---           RETURN NEW;---
---           END;---
---           $$ LANGUAGE plpgsql;---
------
---           DROP TRIGGER IF EXISTS insert_account ON account;---
---           CREATE TRIGGER insert_account AFTER INSERT  ON account FOR EACH ROW EXECUTE PROCEDURE insert_account_status();---
            """)

        stable = get_account_status_table()
        if not stable.exists(engine):
            stable.create(engine)
#            conn.execute(""" 
#            CREATE OR REPLACE FUNCTION update_accstatus_table(name text,host text) RETURNS VOID AS
#            $$
#            BEGIN
#                    UPDATE account_status SET last_login_time = NOW(),chost = host WHERE uname = name;
#                    IF NOT FOUND THEN
#                        INSERT INTO account_status(uname,is_login,last_login_time,chost) VALUES(name,True,'now',host);
#            END;
#            $$
#            LANGUAGE plpgsql;
#            """)

        vtable = get_vendor_table()
        if not vtable.exists(engine):
            vtable.create(engine)
            """每插入一条新的厂商名到vendor表，就为这个名字新建一张表"""
            conn.execute("""
            CREATE FUNCTION add_vendor() RETURNS TRIGGER AS $$
            BEGIN
            EXECUTE format('
            CREATE TABLE IF NOT EXISTS "'||new.vname||'" (
              devid uuid NOT NULL PRIMARY KEY,
              is_active boolean NOT NULL DEFAULT true,
              last_login_time timestamp without time zone NOT NULL DEFAULT now(),
              last_logout_time timestamp without time zone NOT NULL DEFAULT now(),
              is_online boolean NOT NULL default False,
              chost character varying(22) NOT NULL ,
              data bytea NOT NULL 
              );');
              RETURN NEW;
            END;
            $$LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS insert_vendor ON vendor;
            CREATE TRIGGER insert_vendor AFTER INSERT OR UPDATE ON vendor FOR EACH ROW EXECUTE PROCEDURE add_vendor();
            """)
        conn.close()

