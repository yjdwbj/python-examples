#-*- coding: utf-8 -*-
from flask import Flask
import os
from flask.ext.admin import Admin,BaseView,expose
from flask.ext.admin.contrib.sqla import ModelView
from flask.ext.sqlalchemy import SQLAlchemy
import json

fmjson = None

class MyView(BaseView):
    @expose('/')
    def index(self):
        return self.render('admin/item_adm.html')



app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)

admin = Admin(app)
admin.add_view(MyView(name=u'电台管理'))
from read_fmaddr import ReadIni

from config import FMFILE,IMGPATH
fmjson = json.dumps(ReadIni(FMFILE))

from app import views,models
from models import RadioLink
admin.add_view(ModelView(RadioLink,db.session))
