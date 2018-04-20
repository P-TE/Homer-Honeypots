# Import flask dependencies
from flask import Blueprint, request, render_template, \
                  flash, g, session, redirect, url_for
from os import getcwd
import uuid
import crypt
from app import db
from utils import requires_roles
from models import Honey, Config


# Define the blueprint: 'auth', set its url prefix: app.url/auth
deploy = Blueprint('deploy', __name__)

def generateAdConf(user,password,dom):
    filename = '/output/'+str(uuid.uuid4())[:13]+'.txt'
    path = getcwd()+filename
    creds = user+'/'+password+'/'+dom
    try:
        with open(path,'w') as file:
            file.write(creds)
    except IOError:
        return False
    return filename

def generateSshConf(ssh): # TODO => decomment
    host = render_template('hosts_template', ssh=ssh)
    path = '/opt/ansible/host'
    try:
        with open(path,'w') as file:
            file.write(host)
    except IOError:
        return False
    playbook = render_template('playbook_template.yml', ssh=ssh)
    path = '/opt/ansible/playbook.yml'
    try:
        with open(path,'w') as file:
            file.write(playbook)
    except IOError:
        return False
    return True


def generateFtpConf(ftp): # TODO => decomment
    ftp['passFTP'] = crypt.crypt(ftp['passFTP'],'$1$oihivoezvozfoz$') #TODO : changer via un secret 
    config_ip = Config.query.filter_by(key='syslog_ip').first()
    config_port = Config.query.filter_by(key='syslog_port').first()
    host = render_template('hosts_template', ftp=ftp, ip=config_ip.value, port=config_ip.value)
    path = '/opt/ansible/host'
    try:
        with open(path,'w') as file:
            file.write(host)
    except IOError:
        return False

    playbook = render_template('playbook_template.yml', ftp=ftp)
    path = '/opt/ansible/playbook.yml'
    try:
        with open(path,'w') as file:
            file.write(playbook)
    except IOError:
        return False
    return True

@deploy.route("/install", methods=['GET','POST'])
@requires_roles('all')
def install():
    host = request.headers.get('Host')

    if request.method == "POST":
        file = ""
        result = request.form.to_dict()

        if result['submit'] == 'ad':
            file = generateAdConf(request.form.get('userAD'), request.form.get('passAD'), request.form.get('domAD'))
            if file:
                honeyAD = Honey(honeytype="Honeypot Active Directory",desc=file)
                db.session.add(honeyAD)
                db.session.commit()

        if result['submit'] == 'ssh':
            if generateSshConf(result):
                syslog_status = ""
                config_ip = Config.query.filter_by(key='syslog_ip').first()
                if config_ip.value:
                    syslog_status = "\n Syslog install&eacute;"
                session['honeyinstall'] = True
                session['honeytype'] = "Honeypot SSH"
                session['honeyip'] = request.form.get('ipSSH').split(':')[0]
                session['honeydesc'] = request.form.get('bannerSSH') + syslog_status

        if result['submit'] == 'ftp':
            if generateFtpConf(result):
                syslog_status = ""
                config_ip = Config.query.filter_by(key='syslog_ip').first()
                if config_ip.value:
                    syslog_status = "Syslog install&eacute;"
                session['honeyinstall'] = True
                session['honeytype'] = "Honeypot FTP"
                session['honeyip'] = request.form.get('ipFTP').split(':')[0]
		session['honeydesc'] = syslog_status


        return render_template('resume.html', result=result, file=file)
    else:
        return render_template('install.html', host=host)
