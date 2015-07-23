import os

basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir,'app.db')
SQLALCHEMY_MIGRATE_REPO= os.path.join(basedir,'db_repository')
CSRF_ENABLED = True
SECRET_KEY ='7922ae66fb5a54a92e8d2cccde4178e5d7a50b22781b2c96f7ca03e358fb5e7f'

USERNAME='lcy'
PASSWORD='lcy123'
FMFILE='fm_address.txt'
IMGPATH='images'
