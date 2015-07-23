from flask.ext.wtf import Form
from wtforms import StringField,BooleanField,TextField,PasswordField
from wtforms.validators import DataRequired

class AdminForm(Form):
    name = StringField('uname')
    password = PasswordField('passwd')
