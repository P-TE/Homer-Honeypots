# Import flask dependencies
from flask import Blueprint, request, render_template, \
                  flash, g, session, redirect, url_for, send_from_directory, Response
import utils
from utils import requires_roles
import socket
from app import db
from models import User, Honey, Config
import bcrypt
from shelljob import proc
import time


# Define the blueprint: 'auth', set its url prefix: app.url/auth
views = Blueprint('views', __name__)

@views.route('/setup', methods=['GET','POST'])
def setup():
    if not utils.is_setup():
        if request.method == "POST":
            username = request.form['name']
            password = bcrypt.hashpw(request.form.get('password').encode('utf-8'), bcrypt.gensalt())
            admin = User(username=username,password=password,role="all")
            syslog_ip = Config(key="syslog_ip", value=None)
            syslog_port = Config(key="syslog_port", value=None)
            db.session.add(admin)
	    db.session.add(syslog_ip)
	    db.session.add(syslog_port)
            db.session.commit()
            installed = utils.set_config('installed', True)
            return redirect('/')
        else:
            return render_template('register.html')
    else:
        return redirect('/')

@views.route('/login', methods=['GET','POST'])
def login():
    if utils.is_setup():
        if request.method == "POST":
            username = request.form['name']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            if user:
                if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                    session['role'] = user.role
                    session['username'] = user.username
                    return redirect('/')
            error = "Mauvais creds !"
            return render_template('login.html', error=error)
        else:
            return render_template('login.html')
    else:
        return redirect('/setup')

@views.route('/logout', methods=['GET'])
def logout():
    if utils.authed():
        session.clear()
        return redirect('/login')
    else:
        return redirect('/login')


@views.route('/', methods=['GET'])
@requires_roles('all')
def index():
    ftps = Honey.query.filter_by(honeytype="Honeypot FTP").all()
    ads = Honey.query.filter_by(honeytype="Honeypot Active Directory").all()
    sshs = Honey.query.filter_by(honeytype="Honeypot SSH").all()
    return render_template('index.html', sshs=sshs, ads=ads, ftps=ftps)


@views.route("/api", methods=['POST'])
@requires_roles('all')
def api():
    result = request.form
    ip = request.form.getlist('ip')[0]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect((ip.split(':')[0], int(ip.split(':')[1])))
        ssh = '1'
    except socket.error as e:
        ssh = '0'
    s.close()
    return ssh

@views.route("/stream", methods=['GET'])
@requires_roles('all')
def stream():
    if session["honeyinstall"]:
        success = False
        g = proc.Group()
        #p = g.run( [ "ls", "-la"] )
        p = g.run( [ "sh", "/opt/ansible/run_ansible.sh"] )
        def read_process():
            while g.is_pending():
                lines = g.readlines()
                for proc, line in lines:
                    time.sleep(.1)
                    yield "data:" + line + "\n\n"

        # TODO mettre un condition en matchant le contenu de line (si line == install ok alors add honey)
   
        honey = Honey(honeytype=session['honeytype'],ip=session['honeyip'],desc=session['honeydesc'])
        db.session.add(honey)
        db.session.commit()
        session['honeyinstall'] = False
        session.pop('honeytype')
        session.pop('honeyip')
        session.pop('honeydesc')

        return Response( read_process(), mimetype= 'text/event-stream' )
    else:
        return Response("Nope", mimetype= 'text/event-stream')


@views.route("/options", methods=['GET','POST'])
@requires_roles('all')
def options():
    if request.method == "POST":
        msg = ""
        status = request.form.get('status')
        if status:
            ip = request.form.get('syslog_ip')
            port = request.form.get('syslog_port')
            if not ip or not port:
                return render_template('config.html', msg="Formulaire invalide")

            config_ip = Config.query.filter_by(key='syslog_ip').first()
            config_port = Config.query.filter_by(key='syslog_port').first()
            config_ip.value = ip
            config_port.value = port
            db.session.commit()
            msg = "Configuration valide"
        else:
            config_ip = Config.query.filter_by(key='syslog_ip').first()
            config_port = Config.query.filter_by(key='syslog_port').first()
            config_ip.value = ""
            config_port.value = ""
            db.session.commit()
            msg = "Config suppr"
        return render_template('config.html', msg=msg, syslog_ip=config_ip, syslog_port=config_port)
    else:
        config_ip = Config.query.filter_by(key='syslog_ip').first()
        config_port = Config.query.filter_by(key='syslog_port').first()
        return render_template('config.html', syslog_ip=config_ip, syslog_port=config_port)
    


@views.route("/output/<id>", methods=['GET'])
@requires_roles('all')
def get_cred(id):
    return send_from_directory('../output', id)


@views.route('/honey/edit/<id>', methods=['GET','POST'])
@requires_roles('all')
def editHoney(id):
    if request.method == "POST":
        honey = Honey.query.filter_by(id=id).first()
        ip = request.form.get('ip')
        desc = request.form.get('desc')
        honey.ip = ip 
        honey.desc = desc
        db.session.commit()
        return render_template('honey.html',honey=honey)
    else:
        honey = Honey.query.filter_by(id=id).first()
        return render_template('honey.html',honey=honey)


@views.route('/honey/delete/<id>', methods=['GET'])
@requires_roles('all')
def deleteHoney(id):
    honey = Honey.query.filter_by(id=id).first()
    db.session.delete(honey)
    db.session.commit()

    return redirect('/')
