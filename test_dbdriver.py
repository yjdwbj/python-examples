#!/opt/stackless-279/bin/python

from dbdriver import *
initdb()
v1 = Vendor(vname='0000000')
v2 = Vendor(vname='2000000')

u1 = Account(uname="70d83b250f154eecb2c8e453094ed8d600000000717e8164",pwd="70d83b250f154eecb2c8e453094ed8d600000000717e8164")
session.merge(v1)
session.merge(v2)
session.merge(u1)
d1 = VendorDev("0000000")
d1.devid="70d83b250f154eecb2c8e453094ed8d6"
session.merge(d1)
session.commit()
print [n.vname for n in session.query(Vendor).all()]
for i in session.query(Vendor).all():
    print i.vname

