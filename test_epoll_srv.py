#coding=utf-8
#import epoll_srv
import struct
import binascii
import uuid
import unittest

from sockbasic import *
from pg_driver import *

class dumpclass:
    pass

class TestEpollSrv(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass

#    def gen_uuid(self):
#        u = ''.join([str(uuid.uuid4()).replace('-',''),binascii.hexlify('test')])
#        return ''.join([u,epoll_srv.get_jluuid_crc32(u)])
#
#    def test_gen_ten_jluuid(self):
#        tn = ''
#        n = 0
#        while n < 10:
#            tn = ''.join([tn,self.gen_uuid()])
#            n +=1
#        return tn
#
#    def test_handle_allocate_request(self):
#        return
#        res = dumpclass()
#        res.method=STUN_METHOD_ALLOCATE
#        res.fileno=5
#        res.attrs={}
#        res.attrs[STUN_ATTRIBUTE_UUID] = (STUN_ATTRIBUTE_UUID,24,binascii.unhexlify(self.gen_uuid()))
#        rbuf = epoll_srv.handle_allocate_request(res)
#        self.assertTrue(rbuf)
#
#
#    def test_handle_bind_device(self):
#        res = dumpclass()
#        res.method=STUN_METHOD_CHANNEL_BIND
#        res.fileno=5
#        muuid = self.test_gen_ten_jluuid()
#        res.attrs={}
#        res.attrs[STUN_ATTRIBUTE_MUUID] = (STUN_ATTRIBUTE_MUUID,24*10,binascii.unhexlify(muuid))
#        rbuf = epoll_srv.handle_app_bind_device(res)
#        self.assertTrue(rbuf)
#
#
#    def test_split_uuid(self):
#        muuid = self.test_gen_ten_jluuid()
#        self.assertEqual(len(muuid),(48 * 10))
#        mlist = epoll_srv.split_muuid(muuid)
#        self.assertEqual(len(mlist),10)
#        p = [epoll_srv.check_jluuid(n) for n in mlist]
#        self.assertEqual([x for x in p if x] ,[])
#        [epoll_srv.bind_each_uuid(n,5) for n in mlist]
#        assert epoll_srv.gClass.appbinds[5]
#        print epoll_srv.gClass.appbinds[5]
#
#    def test_check_packet_vaild(self):
#        buf='4a4c00300000000000000000000000030000000080010018373163cda13c4ca9b9e07ac9bb26d58074657374e1494701000d0004000000a0001300087465737464617461a1c7c346'
#        res = epoll_srv.check_packet_vaild(buf)
#        self.assertEqual(res,0)
#        self.assertFalse(res)


    def test_check_user_exist(self):
        buf='4a4c0001002000000000000000000013000000030013000278620000efff49a6'
        buf='4a4c0001002000000000000000000013000000000013000278620000d6727563'
        res = get_packet_head_class(buf[:STUN_HEADER_LENGTH])
        print res.__dict__


    def test_db_insert_exist(self):
        db = PostgresSQLEngine()
        pwd = 'a42617fa30062fc163447ba157174d5a'
        db.insert_account_table('www',pwd.decode('hex'),'ftpwd',"127.0.0.1:9999")

    def test_db_update_exist(self):
        db = PostgresSQLEngine()
        pwd = 'a42617fa30062fc163447ba157174d5a'
        res = db.update_account_table('www',pwd.decode('hex'),'ftpwd',True,"127.0.0.1:9999")
        self.assertTrue(res)

    def test_db_update_not_exist(self):
        db = PostgresSQLEngine()
        pwd = 'a42617fa30062fc163447ba157174d5a'
        res = db.update_account_table('ttt',pwd.decode('hex'),'ftpwd',True,"127.0.0.1:9999")
        self.assertFalse(res)

    def test_db_insert_devtable(self):
        db = PostgresSQLEngine()
        pwd = 'a42617fa30062fc163447ba157174d5a'
        uuid = 'c1ed939c189c849bee8cbdbc00b250692653716626a67c9f'
        uuid = '059a94d878214e2a946a40328197284c'
        #res = db.insert_devtable("00000000",uuid,'128.0.0.1','ab12'.decode('hex'))
        self.assertFalse(res)

    def test_db_insert_bind_table(self):
        db = PostgresSQLEngine()
        pwd = 'a42617fa30062fc163447ba157174d5a'
        uuid = 'c1ed939c189c849bee8cbdbc00b250692653716626a67c9f'
        #res = db.insert_bind_table('kini',uuid,pwd.decode('hex'))
        self.assertFalse(res)

    def test_db_pull_bind_table(self):
        db = PostgresSQLEngine()
        data = db.pull_bind_table('kini')
        print data

    def test_db_delete_bind_table(self):
        db = PostgresSQLEngine()
        uname = 'kini'
        uuid = 'c1ed939c189c849bee8cbdbc00b250692653716626a67c9f'
        res = db.delete_bind_table(uname,uuid)
        print res
        





if __name__ == '__main__':
    unittest.main()
