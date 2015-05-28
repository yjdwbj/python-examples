#!/opt/stackless-279/bin/python

from datetime import datetime
from sqlalchemy.exc import *
from sqlalchemy import Table,create_engine,Column,func,or_,not_,and_,ForeignKey,String,Integer,BigInteger,Date,MetaData,DateTime,Boolean,VARCHAR,sql
from sqlalchemy.dialects import postgresql as pgsql
from sqlalchemy.dialects.postgresql import BYTEA,UUID,TIMESTAMP
from sqlalchemy.pool import QueuePool
from sqlalchemy.orm import sessionmaker,relationship,backref,mapper,create_session,configure_mappers,clear_mappers,class_mapper,object_mapper
from sqlalchemy.ext.declarative import declarative_base

SQLDriver='postgresql+psycopg2cffi://postgres:lcy123@192.168.25.105:5432/nath'

eng = create_engine(SQLDriver)

BaseModel = declarative_base()
#g_vendordev = dict()
#g_bindtable = dict()

class Vendor(BaseModel):
    __tablename__ = 'vendor'
    vname = Column(VARCHAR(8),nullable=False,primary_key=True)

def Session():
    S = sessionmaker(bind=eng,autoflush=True,autocommit=False,expire_on_commit=True)
    return S()

def VendorDev(tname):
    #if g_vendordev.has_key(tname):
    #    return g_vendordev[tname]
    #g_vendordev[tname] = 
    return type("NewClass",(BaseModel,),{"__tablename__":tname,
                                           #"__init__":settnlname,
                                           "extend_existing":True,
                                           "devid":Column(UUID,primary_key=True,unique=True,nullable=False),
                                           "is_active":Column(Boolean,nullable=False,default=True),
                                           "last_login_time":Column(TIMESTAMP,nullable=False,default=datetime.now()),
                                           "last_logout_time":Column(TIMESTAMP,nullable=False,default=datetime.now()),
                                           "is_online":Column(Boolean,nullable=False,default=True),
                                           "chost":Column(VARCHAR(22),nullable=False,default=''),
                                           "data":Column(BYTEA,default='')
                                           })
    #return g_vendordev[tname]



def AccBindTable(tname):
    #if g_bindtable.has_key(tname):
    #    return g_bindtable[tname]
    #g_bindtable[tname] = 
    return type("BindClass",(BaseModel,),{"__tablename__":tname,
            "extend_existing":True,
            'devid':Column(VARCHAR(48),nullable=False,primary_key=True),
            'pwd':Column(BYTEA,default=''),
            'reg_time':Column(TIMESTAMP,nullable=False,default=datetime.now())
            })
    #return g_bindtable[tname]

class Account(BaseModel):
    __tablename__ = 'account'
    uname = Column(VARCHAR(255),nullable=False,primary_key=True)
    pwd = Column(BYTEA)
    is_active = Column(Boolean,default=True)
    reg_time = Column(TIMESTAMP,default=datetime.now())

class AccountStatus(BaseModel):
    __tablename__ = 'account_status'
    uname = Column(VARCHAR(255),ForeignKey('account.uname'),primary_key=True)
    is_login = Column(Boolean,default=False)
    last_login_time = Column(TIMESTAMP,default=datetime.now())
    last_logout_time = Column(TIMESTAMP,default=datetime.now())
    chost = Column(VARCHAR(22),nullable=False,default='')
    #account = relationship("Account",backref='account')


def initdb():
    BaseModel.metadata.create_all(eng)
    session = Session()
#    session.execute("""
#    CREATE OR REPLACE FUNCTION add_vendor() RETURNS TRIGGER AS $$
#    BEGIN
#    EXECUTE format('
#    CREATE TABLE IF NOT EXISTS "'||new.vname||'" (
#      devid uuid NOT NULL PRIMARY KEY,
#      is_active boolean NOT NULL,
#      last_login_time timestamp without time zone NOT NULL,
#      is_online boolean NOT NULL,
#      chost character varying(22) NOT NULL,
#      data bytea 
#      );');
#      RETURN NEW;
#    END;
#    $$LANGUAGE plpgsql;
#                
#---    DROP TRIGGER IF EXISTS insert_vendor ON vendor;
#---    CREATE TRIGGER insert_vendor AFTER INSERT OR UPDATE ON vendor FOR EACH ROW EXECUTE PROCEDURE add_vendor();
#---
#---    CREATE OR REPLACE FUNCTION add_bindtable() RETURNS TRIGGER AS $BODY$
#---    BEGIN
#---    EXECUTE format('
#---    CREATE TABLE IF NOT EXISTS "'||NEW.uname||'"  (
#---      devid VARCHAR(48) NOT NULL PRIMARY KEY,
#---      pwd BYTEA,
#---      reg_time timestamp with time zone DEFAULT now()
#---      );');
#---    RETURN NEW;
#---    END;
#---    $BODY$ LANGUAGE plpgsql;
#---
#---    
#---    DROP TRIGGER IF EXISTS add_bind ON account;
#---    CREATE TRIGGER add_bind AFTER INSERT OR UPDATE ON account FOR EACH ROW EXECUTE PROCEDURE add_bindtable();
#    
#
#    CREATE OR REPLACE FUNCTION insert_account_status() RETURNS TRIGGER as 
#    $$
#    BEGIN
#    INSERT into account_status (uname,is_login,last_login_time,chost) VALUES(quote_ident(NEW.uname),False,'now()','');
#    RETURN NEW;
#    END;
#    $$ LANGUAGE plpgsql;
#
#    DROP TRIGGER IF EXISTS insert_account ON account;
#    CREATE TRIGGER insert_account AFTER INSERT  ON account FOR EACH ROW EXECUTE PROCEDURE insert_account_status();
#
#
#    """)
    session.commit()
    session.close()

