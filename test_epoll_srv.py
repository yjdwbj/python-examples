#coding=utf-8
#import epoll_srv
import struct
import binascii
import uuid
import unittest

from sockbasic import *

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

    def test_stun_buf_to_list(self):
        buf="00060030353062303139623263326338343662343966306363323531643464323339643430303030303030303132383835343734000800203f0acccc2ebf8f8f955224c55306ed51a7d6040ec154dc92c59db4105761be58"
        mbuf="4a4c0001002c00000a6200000b0700070200002200130010313432393531373132302e353730353068a9a90e4a4c0001002c00000a6200000b0700070200002300130010313432393531373132302e35393231329e4a2de5"
        mbuf="4a4c0001002c00000643000006e800060300005600130010313432393537383933372e343038333153b2fea94a4c0001002c00000643000006e800060300005600130010313432393537383933372e343336313790ccbbfa4a4c0001002c00000643000006e800060300005600130010313432393537383933372e34333632395c59c53e4a4c0001002c00000643000006e800060300005600130010313432393537383933372e34333633354cf4b8544a4c0001002c00000643000006e800060300005600130010313432393537383933372e343336343104d8ea8a4a4c0001002c00000643000006e800060300005600130010313432393537383933372e34333634369abc7f294a4c0001002c00000643000006e800060300005600130010313432393537383933372e34333635311dc3dbcb4a4c0001002c00000643000006e800060300005600130010313432393537383933372e343336353683a74e684a4c0001002c00000643000006e800060300005600130010313432393537383933372e343336363136ee88084a4c0001002c00000643000006e800060300005600130010313432393537383933372e3433363636a88a1dab4a4c0001002c00000643000006e800060300005600130010313432393537383933372e343336373058f289df4a4c0001002c00000643000006e800060300005600130010313432393537383933372e343336373528987d504a4c0001002c00000643000006e800060300005600130010313432393537383933372e3433363830df6a95104a4c0001002c00000643000006e800060300005600130010313432393537383933372e3433363834d80751094a4c0001002c00000643000006e800060300005600130010313432393537383933372e3433363839a6b62db44a4c0001002c00000643000006e800060300005600130010313432393537383933372e34333639335f78f5eb"
        mbuf="4a4c0001002c00001a9300001a7d00070300001d00130010313432393538363132312e3532363632131750734a4c0001002c00001a9300001a7d00070300001d00130010313432393538363132312e3532363632131750734a4c0001002c00001a9300001a7d00070300001d00130010313432393538363135362e36333638385d3fbec14a4c0001002c00001a9300001a7d00070300001d00130010313432393538363135362e363935363649ffe0754a4c0001002c00001a9300001a7d00070300001d00130010313432393538363135362e3639353832d01109e24a4c0001002c00001a9300001a7d00070300001d00130010313432393538363135362e3639353931500369194a4c0001002c00001a9300001a7d00070300001d00130010313432393538363135362e363935393829dfd1bd4a4c0001002c00001a9300001a7d00070300001d00130010313432393538363135362e363936303584eaa8104a4c0001002c00001a9300001a7d00070300001d00130010313432393538363135362e36393631319a9c5d484a4c0001002c00001a9300001a7d00070300001d00130010313432393538363135362e363936313773fff87d4a4c0001002c00001a9300001a7d00070300001d00130010313432393538363135362e363936323228b85f314a4c0001002c00001a9300001a7d00070300001d00130010313432393538363135362e3639363238c86db62f4a4c0001002c00001a9300001a7d00070300001d00130010313432393538363135362e36393634370e880c384a4c0001002c00001a9300001a7d00070300001d00130010313432393538363135362e3639363535f99d5c554a4c0001002c00001a9300001a7d00070300001d00130010313432393538363135362e3639363631d5ddcb8f4a4c0001002c00001a9300001a7d00070200001d00130010313432393538363135362e36393636382d24160c4a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e3639363735b0b5bc344a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e3639363831304064e24a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e3639363836ae24f1414a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e3639363932b05204194a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e3639363937c038f0964a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e36393730331755e5f14a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e3639373039f7800cef4a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e3639373134902a41134a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e3639373230bc6ad6c94a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e3639373235cc0022464a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e3639373331d276d71e4a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e36393733364c1242bd4a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e3639373432043e10634a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e36393734377454e4ec4a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e36393735336a2211b44a4c0001002c00001a9300001a7d00070300001e00130010313432393538363135362e3639373538fdf0c83c"
        mbuf="4a4c0001002c00001ceb00001d4900060300001400130010313432393538363132352e3031333534b964e7e84a4c0001002c00001ceb00001d4900060300001400130010313432393538363132352e3031333631e22340a44a4c0001002c00001ceb00001d4900060300001400130010313432393538363132352e30313336370b40e5914a4c0001002c00001ceb00001d4900060300001400130010313432393538363132352e3031333733153610c94a4c0001002c00001ceb00001d4900060300001400130010313432393538363132352e3031333739f5e3f9d74a4c0001002c00001ceb00001d4900060300001400130010313432393538363132352e30313338357bcda9334a4c0001002c00001ceb00001d4900060300001400130010313432393538363132352e3031333932fcb20dd14a4c0001002c00001ceb00001d4900060300001400130010313432393538363132352e30313339378cd8f95e4a4c0001002c00001ceb00001d4900060200001400130010313432393538363132352e3031343033de1df5ac4a4c0001002c00001ceb00001d4900060200001400130010313432393538363132352e30313430393ec81cb24a4c0001002c00001ceb00001d4900060200001400130010313432393538363132352e30313431345962514e4a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e30313432306bdd202d4a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e30313432351bb7d4a24a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e303134333072c6116c4a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e303134333502ace5e34a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e30313433390b1aa9c84a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e30313434343aea43b24a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e3031343439445b3f0f4a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e303134353423f172f34a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e30313435395d400e4e4a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e303134363408dc21304a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e3031343639766d5d8d4a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e303134373411c710714a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e303134373818715c5a4a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e3031343833083b991d4a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e30313438389fe940954a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e30313439331120a85c4a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e303134393886f271d44a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e3031353033c12079224a4c0001002c00001ceb00001d4900060300001500130010313432393538363132352e303135303856f2a0aa"
        m1 = "4a4c0001002c00001a9200001a7c00070300001d00130010313432393538363132312e353139323609944a2d4a4c0001002c00001a9200001a7c00070300001d00130010313432393538363135362e36333731337a8645a74a4c0001002c00001a9200001a7c00070300001d00130010313432393538363135362e3639373736330bf6ca4a4c0001002c00001a9200001a7c00070300001d00130010313432393538363135362e36393738352d9abbbf4a4c0001002c00001a9200001a7c00070300001d00130010313432393538363135362e36393739344386ba684a4c0001002c00001a9200001a7c00070300001d00130010313432393538363135362e3639383031e972b2934a4c0001002c00001a9200001a7c00070300001d00130010313432393538363135362e3639383037001117a64a4c0001002c00001a9200001a7c00070300001d00130010313432393538363135362e36393831331e67e2fe4a4c0001002c00001a9200001a7c00070300001d00130010313432393538363135362e363938313889b53b764a4c0001002c00001a9200001a7c00070300001d00130010313432393538363135362e3639383234ab2e249e4a4c0001002c00001a9200001a7c00070300001d00130010313432393538363135362e3639383330b558d1c64a4c0001002c00001a9200001a7c00070300001d00130010313432393538363135362e3639383335c53225494a4c0001002c00001a9200001a7c00070300001d00130010313432393538363135362e36393834318d1e77974a4c0001002c00001a9200001a7c00070300001d00130010313432393538363135362e3639383437647dd2a24a4c0001002c00001a9200001a7c00070200001d00130010313432393538363135362e36393835328c29724b4a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e363938353896c77c914a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e36393836332a38f6da4a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e3639383639caed1fc44a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e3639383735da4062ae4a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e36393838302db28aee4a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e3639383836c4d12fdb4a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e363938393143ae8b394a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e3639383937aacd2e0c4a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e36393930320aa70bfd4a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e3639393038ea72e2e34a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e3639393134fadf9f894a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e3639393139846ee3344a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e3639393234d1f2cc4a4a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e3639393330cf8439124a4c0001002c00001a9200001a7c00070300001e00130010313432393538363135362e363939333626e79c27"
        mbuf="4a4c0001002c000029200000294d00070200000f00130010313432393834323936392e3438363738c09f0c324a4c0001002c000029200000294d00070300000e00130010313432393834323936392e343836383527498af94a4c0001002c000029200000294d00070300000e00130010313432393834323936392e3438363932a0362e1b4a4c0001002c000029200000294d00070300000e00130010313432393834323936392e3438363932a0362e1b4a4c0001002c000029200000294d00070300000e00130010313432393834323936392e3438363932a0362e1b4a4c0001002c000029200000294d00070300000e00130010313432393834323936392e3438363932a0362e1b4a4c0001002c000029200000294d00070200001000130010313432393834333132352e39303839350716ac3f4a4c0001002c000029200000294d00070200001000130010313432393834333132352e3930393035d7167d414a4c0001002c000029200000294d00070200001000130010313432393834333132352e3930393135ce0d4c004a4c0001002c000029200000294d00070200001000130010313432393834333132352e393039323492272f554a4c0001002c000029200000294d00070200001000130010313432393834333132352e393039333315588bb74a4c0001002c000029200000294d00070200001000130010313432393834333132352e3930393431b4177c5c4a4c0001002c000029200000294d00070200001000130010313432393834333132352e3930393438cdcbc4f84a4c0001002c000029200000294d00070200001000130010313432393834333132352e3930393535aa6189044a4c0001002c000029200000294d00070200000f00130010313432393834333132352e393039363181d0831c4a4c0001002c000029200000294d00070200001000130010313432393834333132352e3930393638fffda67a4a4c0001002c000029200000294d00070200001000130010313432393834333132352e39303937359857eb864a4c0001002c000029200000294d00070200001000130010313432393834333132352e393039383118a233504a4c0001002c000029200000294d00070200001000130010313432393834333132352e39303938391679bb624a4c0001002c000029200000294d00070200001000130010313432393834333132352e39303939369fdd97b24a4c0001002c000029200000294d00070300000f00130010313432393834333132352e39313030330fcc7c7b4a4c0001002c000029200000294d00070300000f00130010313432393834333132352e39313031308fde1c804a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931303137976e71c64a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931303234254a73bf4a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313033303b3c86e74a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931303336d25f23d24a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313034329a73710c4a4c0001002c000029200000294d00070300000f00130010313432393834333132352e39313034398b7550614a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931303536840584544a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931303632a845138e4a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313036393f97ca064a4c0001002c000029200000294d00070300000f00130010313432393834333132352e3931303735a9ee4f894a4c0001002c000029200000294d00070200001000130010313432393834333132352e393130383341c10e964a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931303931b6d45efb4a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931303939b80fd6c94a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931313036f8b01a264a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931313132e6c6ef7e4a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931313139711436f64a4c0001002c000029200000294d00070300000f00130010313432393834333132352e3931313235d55bd1fb4a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931313332d4f08dfc4a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931313339432254744a4c0001002c000029200000294d00070200001000130010313432393834333132352e393131343505d58e984a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313135311ba37bc04a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931313538627fc3644a4c0001002c000029200000294d00070300000f00130010313432393834333132352e39313136375f3975d34a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931313737c0f6bc774a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931313835a960c1944a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931313934c77cc0434a4c0001002c000029200000294d00070300000f00130010313432393834333132352e39313230309541f9af4a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313231317d89009d4a4c0001002c000029200000294d00070200001000130010313432393834333132352e393132313794eaa5a84a4c0001002c000029200000294d00070300000f00130010313432393834333132352e3931323234a01a5f344a4c0001002c000029200000294d00070200000f00130010313432393834333132352e3931323331484effdd4a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313233383663dabb4a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931323435079330c14a4c0001002c000029200000294d00070200001000130010313432393834333132352e393132353119e5c5994a4c0001002c000029200000294d00070200001000130010313432393834333132352e393132353860397d3d4a4c0001002c000029200000294d00070200001000130010313432393834333132352e393132363442a262d54a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313237305cd4978d4a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931323737c2b0022e4a4c0001002c000029200000294d00070300000f00130010313432393834333132352e3931323833c491221d4a4c0001002c000029200000294d00070300000f00130010313432393834333132352e3931323931338472704a4c0001002c000029200000294d00070300000f00130010313432393834333132352e39313239393d5ffa424a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931333036fb34ce484a4c0001002c000029200000294d00070200001000130010313432393834333132352e393133313392450b864a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313331397290e2984a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931333235500bfd704a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313333314e7d08284a4c0001002c000029200000294d00070200001000130010313432393834333132352e393133333837a1b08c4a4c0001002c000029200000294d00070300000f00130010313432393834333132352e3931333434f78292854a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313335311827afae4a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931333537f1440a9b4a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931333634436008e24a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313337312a11cd2c4a4c0001002c000029200000294d00070200001000130010313432393834333132352e393133373853cd75884a4c0001002c000029200000294d00070300000f00130010313432393834333132352e39313338345b37dd894a4c0001002c000029200000294d00070300000f00130010313432393834333132352e3931333936ac228de44a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931343035677289774a4c0001002c000029200000294d00070200001000130010313432393834333132352e393134313179047c2f4a4c0001002c000029200000294d00070200001000130010313432393834333132352e393134313800d8c48b4a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313432342243db634a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313433314b321ead4a4c0001002c000029200000294d00070200001000130010313432393834333132352e3931343337a251bb984a4c0001002c000029200000294d00070300000f00130010313432393834333132352e39313434336ca911a34a4c0001002c000029200000294d00070200001000130010313432393834333132352e39313435306a6f89bd"
        mlist = split_requests_buf(mbuf)
        for n in mlist:
            print n
        print "--------------------"
        print "list len %d",len(mlist)



if __name__ == '__main__':
    unittest.main()
