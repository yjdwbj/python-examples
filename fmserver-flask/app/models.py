from app import db

class PhoneUser(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    imei = db.Column(db.String(64),index=True,unique=True,primary_key=True)
    pmode = db.Column(db.String(64))
    ostype = db.Column(db.String(128))
    osver = db.Column(db.String(32))
    wh = db.Column(db.String(16))
    phonebreand = db.Column(db.String(64))
    networktype = db.Column(db.Integer)


class RadioLink(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    fmname = db.Column(db.String(128),unique=True)
    link = db.Column(db.String(255))
    #img = db.Column(db.String(255))

    def __repr__(self):
        return '<Title %r>' % (self.fmname)


