#coding=utf-8
import epoll_srv
import struct
import binascii
import uuid
import unittest


from epoll_global import *

class dumpclass:
    pass

class TestEpollSrv(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass

    def gen_uuid(self):
        u = ''.join([str(uuid.uuid4()).replace('-',''),binascii.hexlify('test')])
        return ''.join([u,epoll_srv.get_jluuid_crc32(u)])

    def test_gen_ten_jluuid(self):
        tn = ''
        n = 0
        while n < 10:
            tn = ''.join([tn,self.gen_uuid()])
            n +=1
        return tn

    def test_handle_allocate_request(self):
        res = dumpclass()
        res.method=STUN_METHOD_ALLOCATE
        res.fileno=5
        res.attrs={}
        res.attrs[STUN_ATTRIBUTE_UUID] = (STUN_ATTRIBUTE_UUID,24,binascii.unhexlify(self.gen_uuid()))
        rbuf = epoll_srv.handle_allocate_request(res)
        self.assertTrue(rbuf)


    def test_handle_bind_device(self):
        res = dumpclass()
        res.method=STUN_METHOD_CHANNEL_BIND
        res.fileno=5
        muuid = self.test_gen_ten_jluuid()
        res.attrs={}
        res.attrs[STUN_ATTRIBUTE_MUUID] = (STUN_ATTRIBUTE_MUUID,24*10,binascii.unhexlify(muuid))
        rbuf = epoll_srv.handle_app_bind_device(res)
        self.assertTrue(rbuf)


    def test_split_uuid(self):
        muuid = self.test_gen_ten_jluuid()
        self.assertEqual(len(muuid),(48 * 10))
        mlist = epoll_srv.split_muuid(muuid)
        self.assertEqual(len(mlist),10)
        p = [epoll_srv.check_jluuid(n) for n in mlist]
        self.assertEqual([x for x in p if x] ,[])
        [epoll_srv.bind_each_uuid(n,5) for n in mlist]
        assert epoll_srv.gClass.appbinds[5]
        print epoll_srv.gClass.appbinds[5]



if __name__ == '__main__':
    unittest.main()