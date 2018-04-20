# Import flask dependencies
from flask import Blueprint, request, render_template, \
                  flash, g, session, redirect, url_for
from app import db
from models import User,Config
from functools import wraps

# utils = Blueprint('utils', __name__)

def is_setup():
    setup = Config.query.filter_by(key='installed').first()
    if setup:
        return setup.value
    else:
        return False

def authed():
    if session['username']:
        return True
    else:
        return False

def set_config(key, value):
    config = Config.query.filter_by(key=key).first()
    if config:
        config.value = value
    else:
        config = Config(key, value)
        db.session.add(config)
    db.session.commit()
    return config

def get_current_user_role():
    return session.get('role')

def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if get_current_user_role() not in roles:
                return redirect('/login')
            return f(*args, **kwargs)
        return wrapped
    return wrapper

def is_role(*roles):
    if get_current_user_role() in roles:
        return True
    else:
        return False
