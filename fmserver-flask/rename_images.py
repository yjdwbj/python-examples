import hashlib
import os
from glob import glob
import shutil

def fun(fname):
    nname = hashlib.sha256(fname.split('.')[0]).hexdigest()+'.png'
    shutil.move(fname,'images/'+nname)

if not os.path.exists('images'):
    os.mkdir('images')
[fun(x) for x in glob('*.[Pp][nN][gG]')]
