from app import db
from datetime import datetime

class Config(db.Model):
    __tablename__ = "config"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.Text, unique=True)
    value = db.Column(db.Text)

    def __init__(self, key, value=None):
        self.key = key
        self.value = value



class User(db.Model):
    __tablename__ = "users"

    id = db.Column('user_id',db.Integer , primary_key=True)
    username = db.Column('username', db.String(128), unique=True , index=True)
    password = db.Column('password' , db.String(128))
    role = db.Column('role' , db.String(32))
    registered_on = db.Column('registered_on' , db.DateTime)
 
    def __init__(self, username, password, role):
        self.username = username
        self.password = password
        self.role = role
        self.registered_on = datetime.utcnow()

    def __repr__(self):
        return '<User %r>' % self.username


class Honey(db.Model):
    __tablename__ = "honeypot"

    id = db.Column(db.Integer, primary_key=True)
    honeytype = db.Column(db.String(128))
    ip = db.Column(db.String(15))
    desc = db.Column(db.Text)
    creation = db.Column(db.DateTime)

    def __init__(self,honeytype,ip=None,desc=None):
        self.honeytype = honeytype
        self.ip = ip
        self.desc = desc
        self.creation = datetime.utcnow()
