from app import app
from flask import render_template,flash,request,redirect,request,session,Response
from flask import url_for
from .forms import AdminForm
from app import fmjson
from config import IMGPATH


@app.route('/')
@app.route('/index')
def index():
    resp = Response(response=fmjson, status=200,mimetype='application/json')
    return  (resp)



@app.route('/login',methods=['GET','POST'])
def admin_login():
    error = None
    if request.form['uname'] != app.config['USERNAME']:
        error = 'Invalid username'
    elif request.form['password'] != app.config['PASSWORD']:
        error = 'Invalid Password'
    else:
        session['admin_login'] = True
        flash('You are Admin')
        return redirect(url_for('admin'))
    return render_template('admin/login.html',error =error)

@app.route('/logout')
def admin_logout():
    session.pop('admin_logon',None)
    flash('You are logout')
    return redirect(url_for('show_admin'))

@app.route('/img/<picname>/')
def get_img(picname):
    #resp = Response(response='static/img/'+picname+'.png', status=200,mimetype='image/png')
    #return resp
    return redirect(url_for('static',filename='img/'+picname+'.png'))

@app.route('/json')
def get_json():
    return redirect(url_for('static',filename='json/fm_address.json'))
