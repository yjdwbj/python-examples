#coding=utf-8
#import epoll_srv
import struct
import binascii
import uuid
import unittest
import inspect
from tornado.tcpclient import TCPClient
import ssl

from sockbasic import *
from pg_driver import *
from stackless_gevent_proxy import *

srv = EpollServer()
push_count = 0

class dumpclass:
    pass

class TestEpollSrv(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass


    def test_app_login(self):
        buf = "4a4c000100440000000000000000000100000000000600033939693000080020c4fc18ec501674667276431b6e37a928c28876bdfc438aa5343894d8362c63f2681fad7a".decode('hex')
        exbuf = "4a4c00010018000000000000000000120000000085c06ecd"
        res = get_packet_head_class(buf[:STUN_HEADER_LENGTH])
        res.eattr = STUN_ERROR_NONE
        res.attrs = parser_stun_package(buf[STUN_HEADER_LENGTH:-4])
        res.host = ('192.168.1.1',9999)
        res.fileno = 11
        print "res.attrs",res.attrs
        rstr = srv.handle_app_login_request(res)
        print "login return ",[x.encode('hex') for x in rstr]

    def test_parser_stun_package(self):
        buf = '4a4c0001011c00000000000000000015000000000006000d78787c70706f7c66667c313132000000001300eb7b22617073223a7b22616c657274223a226d65737361\
                6765212121222c226261646765223a312c22736f756e64223a2264656661756c74227d7d7c7b22617073223a7b22616c657274223a226d657373616765212121222c\
                226261646765223a312c22736f756e64223a2264656661756c74227d7d7c7b22617073223a7b22616c657274223a226d657373616765212121222c22626164676522\
                3a312c22736f756e64223a2264656661756c74227d7d7c7b22617073223a7b22616c657274223a226d657373616765212121222c226261646765223a312c22736f75\
                6e64223a2264656661756c74227d7d006e8439ad'
        buf = '4a4c0001011c00000000000000000015000000000006000d78787c70706f7c66667c313132000000001300eb7b22617073223a7b22616c657274223a226d657373616765212121222c226261646765223a312c22736f756e64223a2264656661756c74227d7d7c7b22617073223a7b22616c657274223a226d657373616765212121222c226261646765223a312c22736f756e64223a2264656661756c74227d7d7c7b22617073223a7b22616c657274223a226d657373616765212121222c226261646765223a312c22736f756e64223a2264656661756c74227d7d7c7b22617073223a7b22616c657274223a226d657373616765212121222c226261646765223a312c22736f756e64223a2264656661756c74227d7d006e8439ad'.decode('hex')
        buf = '4a4c0001011c00000000000000000015000000000006000d78787c70706f7c66667c313132000000001300eb7b22617073223a7b22616c657274223a226d657373616765212121222c226261646765223a312c22736f756e64223a2264656661756c74227d7d7c7b22617073223a7b22616c657274223a226d657373616765212121222c226261646765223a312c22736f756e64223a2264656661756c74227d7d7c7b22617073223a7b22616c657274223a226d657373616765212121222c226261646765223a312c22736f756e64223a2264656661756c74227d7d7c7b22617073223a7b22616c657274223a226d657373616765212121222c226261646765223a312c22736f756e64223a2264656661756c74227d7d006e8439ad'.decode('hex')
        res = get_packet_head_class(buf[:STUN_HEADER_LENGTH])
        print "res",res
        attrs = parser_stun_package(buf[STUN_HEADER_LENGTH:-4])
        data = attrs.get(STUN_ATTRIBUTE_DATA,None)
        if '|' in data:
            print data.split('|')


        
        print attrs
        

    def test_apns_push(self):
        lst = ['32065bf32d6bda852120202ea2215f9d77762e1488184eb2557d4cad9d436058'.decode('hex'),"f9f8930776f0a4db585a5f001540a70017c06409a1a6fc44c9da65f937088031".decode("hex"),"115d24422f8ae740befaf13894214471a6bc73dbf298f31c1c83a9021a05556a".decode("hex")]
        errstr = 'not found data from device request'
        default = {'aps':{'sound':'default','badge':len(errstr),'alert':errstr}}
        
        payload = json.dumps(default)
        payloadLen = len(payload)
        deviceToken = lst[0]
        user = 'test'
        #!BH32sH73s
        lst = ['32065bf32d6bda852120202ea2215f9d77762e1488184eb2557d4cad9d436058'.decode('hex'),"f9f8930776f0a4db585a5f001540a70017c06409a1a6fc44c9da65f937088031".decode("hex"),"115d24422f8ae740befaf13894214471a6bc73dbf298f31c1c83a9021a05556a".decode("hex")]
        deviceToken = "95526283f3f8f9668a90e285fdb91f7184d7036088279dcb1616b8c8ee043f84".decode('hex')
        #deviceToken = lst[0]
        #处理与apns的接口 
        apnsPackFormat = "!BIIH32sH" + str(len(payload))+"s"
        host = "gateway.sandbox.push.apple.com"
        host = "gateway.push.apple.com"
        port = 2195

        apns = APNSConnection('push_cert.pem',True)
        msg = struct.pack(apnsPackFormat,1,push_count+1,3,32,deviceToken,payloadLen,payload)
        apns.write(msg)
        time.sleep(1)
        
        print("push apns buffer , user: %s,deviceToken: %s ,payload: %s" % (user,deviceToken,payload))
        print "push msg is",msg.encode('hex')
        data = apns.read()
        if data :
            print "Recv from apns ",data
        apns.close()


"""

    def test_app_register(self):
        buf = "4a4c000100440000000000000000000f00000000000600033939693000080020c4fc18ec501674667276431b6e37a928c28876bdfc438aa5343894d8362c63f25cca2e8c".decode('hex')
        buf = "4a4c000100440000000000000000000f00000000000600036768793000080020ef429fd681536d57eb136f52b818ce80b0c448d3519493de7194e8b13cf0318dcebf65e2".decode('hex')
        exbuf = "4a4c000100200000000000000000000400000000000d000474696d650caf17b6"
        res = get_packet_head_class(buf[:STUN_HEADER_LENGTH])
        res.eattr = STUN_ERROR_NONE
        res.attrs = parser_stun_package(buf[STUN_HEADER_LENGTH:-4])
        res.host = ('192.168.1.1',9999)
        rstr = srv.handle_register_request(res)
        print "register return ",[x.encode('hex') for x in rstr]
        print "register expect buf",exbuf


    def test_dev_login(self):
        buf = "4a4c0001008c0000001e0000001800060300000d00130070c39f3cbeb74bf83ece54de108c72d822b5417cf4b0af6b7e08df83210c91c309c4bced1accac119fff0fed626b208abf68a9f6ac76dd5c90677815f71f64cddfdbe7d8b755cd5ded3cf2c97a0666c6d9a54b6b3d945788e15b2b731d92484e6271c472e84f710db9a54083efe3b33d7dc0b14c0c".decode('hex')
        buf = "4a4c000100340000000000000000000300000000800100188718fe692636179236dcffae08dc548326537166d0d235d3e5368528".decode('hex')
        res = get_packet_head_class(buf[:STUN_HEADER_LENGTH])
        res.eattr = STUN_ERROR_NONE
        res.attrs = parser_stun_package(buf[STUN_HEADER_LENGTH:-4])
        res.host = ('192.168.1.1',9999)
        res.fileno = 22
        rstr = srv.handle_allocate_request(res)
        print "devices  login return ",[x.encode('hex') for x in rstr]



    def test_db_insert_exist(self):
        db = PostgresSQLEngine()
        pwd = 'a42617fa30062fc163447ba157174d5a'
        db.insert_account_table('www',pwd.decode('hex'),'ftpwd',"127.0.0.1:9999")

    def test_db_update_exist(self):
        db = PostgresSQLEngine()
        pwd = 'a42617fa30062fc163447ba157174d5a'
        res = db.update_account_table('www',pwd.decode('hex'),'ftpwd',True,"127.0.0.1:9999")
        self.assertEqual(res,None)

    def test_db_update_not_exist(self):
        print "test",__name__
        db = PostgresSQLEngine()
        pwd = 'a42617fa30062fc163447ba157174d5a'
        res = db.update_account_table('ttt',pwd.decode('hex'),'ftpwd',True,"127.0.0.1:9999")
        self.assertEqual(res,None)

    def test_db_insert_devtable(self):
        db = PostgresSQLEngine()
        pwd = 'a42617fa30062fc163447ba157174d5a'
        uuid = 'c1ed939c189c849bee8cbdbc00b250692653716626a67c9f'
        res = db.insert_devtable("00000000",uuid.decode('hex'),'128.0.0.1','ab12'.decode('hex'))
        self.assertEqual(res,None)

    def test_db_zinsert_bind_table(self):
        db = PostgresSQLEngine()
        pwd = 'a42617fa30062fc163447ba157174d5a'
        uuid = 'c1ed939c189c849bee8cbdbc00b250692653716626a67c9f'
        uuid = '8718fe692636179236dcffae08dc548326537166d0d235d3'
        uuid = '4d63a70763965a1a1ade5216de9c7458265371665ce9cd19'
        res = db.insert_bind_table('kini',uuid.decode('hex'),pwd.decode('hex'))
        self.assertFalse(res)

    def test_db_pull_bind_table(self):
        db = PostgresSQLEngine()
        data = db.pull_bind_table('kini')
        print data

    def test_db_delete_bind_table(self):
        db = PostgresSQLEngine()
        uname = 'kini'
        pwd = 'a42617fa30062fc163447ba157174d5a'
        db.insert_account_table(uname,pwd.decode('hex'),'ftpwd',"127.0.0.1:9999")
        uuid = 'c1ed939c189c849bee8cbdbc00b250692653716626a67c9f'
        res = db.insert_devtable("00000000",uuid.decode('hex'),'128.0.0.1','ab12'.decode('hex'))
        res = db.delete_bind_table(uname,uuid.decode('hex'))
        print res
    """






if __name__ == '__main__':
    unittest.main()
