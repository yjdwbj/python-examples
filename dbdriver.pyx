#!/opt/stackless-279/bin/python

from datetime import datetime
from sqlalchemy.exc import *
from sqlalchemy import Table,create_engine,Column,func,or_,not_,and_,ForeignKey,String,Integer,BigInteger,Date,MetaData,DateTime,Boolean,VARCHAR,sql
from sqlalchemy.dialects import postgresql as pgsql
from sqlalchemy.dialects.postgresql import BYTEA,UUID,TIMESTAMP
from sqlalchemy.pool import QueuePool
from sqlalchemy.orm import sessionmaker,relationship,backref,mapper,create_session
from sqlalchemy.ext.declarative import declarative_base

SQLDriver='postgresql+psycopg2cffi://postgres:lcy123@192.168.25.105:5432/nath'

eng = create_engine(SQLDriver)

Session = sessionmaker(bind=eng)
BaseModel = declarative_base()
session = Session()
metadata = MetaData()

class DynamicTable(object):
    pass

class Vendor(BaseModel):
    __tablename__ = 'vendor'
    vname = Column(VARCHAR(8),nullable=False,primary_key=True)

def VendorDev(tname):
    metadata = MetaData(bind=eng)
    mirco_devices = Table(tname,metadata,
             Column('devid',pgsql.UUID,primary_key=True,unique=True),
             Column('is_active',pgsql.BOOLEAN,nullable=False,default=True),
             Column('last_login_time',pgsql.TIMESTAMP,nullable=False,default=datetime.now()),
             Column('is_online',pgsql.BOOLEAN,nullable=False,default=False),
             Column('chost',pgsql.VARCHAR(22),nullable=False,default=''),
             Column('data',pgsql.BYTEA)
             )
    metadata.create_all()
    mapper(DynamicTable,mirco_devices,non_primary=True)
    return DynamicTable()
    #return create_session(bind=eng,autocommit=False,autoflush=True)


def AccBindTable(tname):
    metadata = MetaData(bind=eng)
    table = Table(tname,metadata,
            Column('devid',pgsql.VARCHAR(48),nullable=False,primary_key=True),
            Column('pwd',pgsql.BYTEA,default=''),
            Column('reg_time',pgsql.TIME,nullable=False,default=datetime.now())
            )
    metadata.create_all()
    mapper(DynamicTable,table)
    return DynamicTable()
    #return create_session(bind=eng,autocommit=False,autoflush=True)


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
    chost = Column(VARCHAR(22),nullable=False,default='')
    account = relationship("Account",backref='account')

def initdb():
    BaseModel.metadata.create_all(eng)
    session.execute("""
    CREATE OR REPLACE FUNCTION add_vendor() RETURNS TRIGGER AS $$
    BEGIN
    EXECUTE format('
    CREATE TABLE IF NOT EXISTS "'||new.vname||'" (
      devid uuid NOT NULL PRIMARY KEY,
      is_active boolean NOT NULL,
      last_login_time timestamp without time zone NOT NULL,
      is_online boolean NOT NULL,
      chost character varying(22) NOT NULL,
      data bytea 
      );');
      RETURN NEW;
    END;
    $$LANGUAGE plpgsql;
                
    DROP TRIGGER IF EXISTS insert_vendor ON vendor;
    CREATE TRIGGER insert_vendor BEFORE INSERT OR UPDATE ON vendor FOR EACH ROW EXECUTE PROCEDURE add_vendor();

    CREATE OR REPLACE FUNCTION add_bindtable() RETURNS TRIGGER AS $BODY$
    BEGIN
    EXECUTE format('
    CREATE TABLE IF NOT EXISTS "'||NEW.uname||'"  (
      devid VARCHAR(48) NOT NULL PRIMARY KEY,
      pwd BYTEA,
      reg_time timestamp with time zone DEFAULT now()
      );');
    RETURN NEW;
    END;
    $BODY$ LANGUAGE plpgsql;

    
    DROP TRIGGER IF EXISTS add_bind ON account;
    CREATE TRIGGER add_bind BEFORE INSERT OR UPDATE ON account FOR EACH ROW EXECUTE PROCEDURE add_bindtable();
    """)
    session.commit()

