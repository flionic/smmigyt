#!/usr/bin/env python3
import ast
import os
import random
import re
import string
import threading
from datetime import datetime, timedelta
from time import sleep

import bcrypt
import requests
from dotenv import load_dotenv
from werkzeug.contrib.fixers import ProxyFix

import flask
from flask import Flask, render_template, request, redirect, url_for, flash, abort, json, make_response
from flask import render_template_string, send_from_directory
from flask.json import jsonify
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_mail import Message
from flask_mail_sendgrid import MailSendGrid


basedir = os.path.abspath(os.path.dirname(__file__))
# TODO: move to configparser (https://hackernoon.com/4-ways-to-manage-the-configuration-in-python-4623049e841b)
load_dotenv(os.path.join(basedir, 'settings.cfg'))

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.config['APP_NAME'] = '1-SMM'
app.config['SERVER_NAME'] = os.getenv('APP_DOMAIN')
app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY', '7-DEV_MODE_KEY-7')
app.config['SESSION_TYPE'] = 'redis'
db_local = 'sqlite:///' + os.path.join(os.path.join(basedir, 'db'), 'main.db')
# db_link = f"mysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}?charset=utf8mb4"
db_link = 'mysql://smm_one:y3./}:dKN522T>fT@localhost/smm_one?charset=utf8mb4'
app.config['SQLALCHEMY_DATABASE_URI'] = db_link
app.config['SQLALCHEMY_MIGRATE_REPO'] = os.path.join(basedir, 'db_repository')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.url_map.strict_slashes = False
login_manager = LoginManager(app)
login_manager.login_view = "users.login"
sess = Session(app)
db = SQLAlchemy(app)
mail = MailSendGrid()


@login_manager.user_loader
def load_user(uid):
    return Users.query.get(int(uid))


@login_manager.unauthorized_handler
def unauthorized_handler():
    flash('Для этого действия требуется авторизация', 'error')
    return redirect(url_for('index'))


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(405)
def go_home(e):
    return redirect(url_for('index'))


class Settings(db.Model):
    __tablename__ = 'settings'
    key = db.Column('key', db.String(24), primary_key=True, unique=True, nullable=False)
    value = db.Column('value', db.Text)

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __repr__(self):
        return "'%s': '%s'" % (self.key, self.value)


class Users(db.Model):
    __tablename__ = "users"
    id = db.Column('user_id', db.Integer, primary_key=True)
    email = db.Column('email', db.String(40), unique=True, nullable=False, index=True)
    password = db.Column('password', db.String(60), nullable=False)
    balance = db.Column('balance', db.Float, nullable=False, default=0)
    # 0 - deactivated, 1 - active, 9 - banned, 7 - admin
    status = db.Column('status', db.Integer, nullable=False, default=0)
    signup_date = db.Column('signup_date', db.DateTime)
    last_login = db.Column('last_login', db.DateTime)

    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.signup_date = datetime.now()

    @staticmethod
    def is_authenticated():
        return True

    @staticmethod
    def is_active():
        return True

    @staticmethod
    def is_anonymous():
        return False

    def get_id(self):
        return str.encode(str(self.id))

    def __repr__(self):
        return '<User %r>' % self.email


class Invoices(db.Model):
    __tablename__ = 'invoices'
    id = db.Column('id', db.Integer, unique=True, nullable=False, primary_key=True, index=True)
    user_id = db.Column('user_id', db.Integer, nullable=False)
    ik_inv_id = db.Column('ik_inv_id', db.String(24), unique=True, nullable=False)
    ik_pm_no = db.Column('ik_pm_no', db.String(24), unique=True)
    ik_state = db.Column('ik_state', db.String(16), default='3')
    ik_inv_prc = db.Column('ik_inv_prc', db.DateTime)
    ik_am = db.Column('ik_am', db.Float)
    ik_cur = db.Column('ik_cur', db.String(3))
    total_am = db.Column('total_am', db.Float())

    def __init__(self, user_id, ik_inv_id, ik_pm_no):
        self.user_id = user_id
        self.ik_inv_id = ik_inv_id
        self.ik_pm_no = ik_pm_no

    def __repr__(self):
        return "<Payment(user_id='%s', ik_inv_id='%s', ik_pm_no='%s', ik_state='%s')>" % (
            self.user_id, self.ik_inv_id, self.ik_pm_no, self.ik_state)


@app.route('/')
def index():
    # todo генерировать pm_id фронтом
    return render_template('index.html', ik={
        'pm_id': 'PM_' + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16)),
        'co_id': app.config['IK_ID_CHECKOUT']
    })


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET' or current_user.is_authenticated:
        return redirect(url_for('index'))
    email = request.form['email']
    password = str.encode(request.form['password'])
    if len(password) < 6:
        flash('Пароль должен состоять минимум из 6 символов', 'error')
    elif Users.query.filter_by(email=email).first():
        flash('Этот email уже зарегистрирован', 'error')
    else:
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        user = Users(email, hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Зарегистрирован пользователь {user.email}')
        login_user(user)
        return redirect(url_for('index'))
    return redirect(url_for('signup'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('Вы уже авторизированы', 'warning')
        return redirect(url_for('index'))
    user = Users.query.filter_by(email=request.form['email']).first()
    if user is None:
        flash('Этот Email не зарегистрирован', 'error')
    # elif bcrypt.checkpw(str.encode(request.form['password']), user.password) is False: # for sqlite
    elif bcrypt.checkpw(str.encode(request.form['password']), str.encode(user.password)) is False:
        flash('Неверный пароль', 'error')
    else:
        login_user(user)
        user.last_login = datetime.now()
        db.session.commit()
        flash(f'Авторизирован {user.email}')
    return redirect(request.args.get('next') or url_for('index'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/settings')
@login_required
def tasks():
    if current_user.status == 7:
        return render_template('settings.html')


@app.route('/tasks')
@login_required
def settings():
    if current_user.status == 7:
        return render_template('tasks.html')


@app.route('/wallet')
def wallet():
    return render_template('wallet.html', ik={
        'pm_id': 'PM_' + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16)),
        'co_id': app.config['IK_ID_CHECKOUT']
    })


# TODO удалить GET метод
@app.route('/payment/pending', methods=['GET', 'POST'])
def payment_status():
    if request.method == 'POST':
        if Invoices.query.filter_by(ik_inv_id=request.form.get('ik_inv_id')).first() is None:
            inv = Invoices(current_user.id, request.form.get('ik_inv_id'), request.form.get('ik_pm_no'))
            db.session.add(inv)
            db.session.commit()
        states = {'success': 'получен', 'canceled': 'не получен', 'waitAccept': 'в ожидании'}
        flash(f'Платеж {states[request.form.get("ik_inv_st")]}')
    return redirect(url_for('index'))


# TODO сверять id кассы, удалить GET метод
@app.route('/payment', methods=['GET', 'POST'])
def payment():
    if request.method == 'POST':
        user = Users.query.filter_by(email=request.form.get('ik_desc').split(' ')[-1]).first()
        inv = Invoices.query.filter_by(ik_inv_id=request.form.get('ik_inv_id')).first()
        if user and (inv is None):
            inv = Invoices(user.id, request.form.get('ik_inv_id'), request.form.get('ik_pm_no'))
            db.session.add(inv)
        if inv.ik_state not in ['5', '7', '8', '9']:
            ik_url = 'https://api.interkassa.com/v1/'
            headers = {'Accept': 'application/json'}
            auth = (app.config['IK_ID'], app.config['IK_KEY'])
            ik_r = requests.get(ik_url + 'co-invoice/' + request.form.get('ik_inv_id'),
                                headers=headers, auth=auth).json()
            # {'status': 'error', 'code': 4,
            #  'data': {'innerCode': 0}, 'message': 'Auth: api not enabled for current user'}
            inv.ik_state = ik_r['data']['state']
            if inv.ik_state == '7':
                inv.ik_inv_prc = ik_r['data']['processed']
                inv.ik_am = float(ik_r['data']['coAmount'])
                inv.ik_cur = ik_r['data']['currencyCodeChar']
                inv.total_am = inv.ik_am
                if ik_r['data']['currencyId'] != 40:
                    ik_curr = requests.get(ik_url + 'currency/' + str(ik_r['data']['currencyId']),
                                           headers=headers, auth=auth).json()
                    inv.total_am *= float(ik_curr['data'][inv.ik_cur]['RUB']['out'])
                user.balance = round(user.balance + inv.total_am, 2)
                print(f'Added {inv.ik_am} {inv.ik_cur} to {user.email}')
        db.session.commit()
        return jsonify('OK'), 200
    return redirect(url_for('index'))


@app.route('/ajax/save/<section>', methods=['POST'])
@login_required
def save_settings(section):
    if current_user.status == 7:
        # threading.Thread(target=update_tasks).start()
        for i in request.json.items():
            if section == 'settings-main':
                Settings.query.filter_by(key=i[0]).first().value = i[1]
            # elif section == 'price':
            #     Types.query.filter_by(type=i[0]).first().new_price = i[1]
        db.session.commit()
        init_settings()
        return jsonify({'response': 1})
    return abort(403)


def init_settings():
    db.create_all()
    # auto-parser
    app.config['APP_NAME'] = Settings.query.filter_by(key='app_name').first().value
    app.config['APP_DOMAIN'] = Settings.query.filter_by(key='app_domain').first().value
    app.config['SERVER_NAME'] = app.config['APP_DOMAIN']
    app.config['IK_ID_CHECKOUT'] = Settings.query.filter_by(key='ik_id_checkout').first().value
    app.config['IK_ID'] = Settings.query.filter_by(key='ik_id').first().value
    app.config['IK_KEY'] = Settings.query.filter_by(key='ik_key').first().value
    app.config['NAKRUTKA_APIKEY'] = Settings.query.filter_by(key='nakrutka_apikey').first().value
    app.config['BIGSMM_APIKEY'] = Settings.query.filter_by(key='bigsmm_apikey').first().value
    # app.config['MAIL_SENDGRID_API_KEY'] = Settings.query.filter_by(key='mailgrid_key').first().value
    # mail.init_app(app)


if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true" or 1 == 1:
    init_settings()


if __name__ == '__main__':
    app.run(host=os.getenv('APP_IP', '0.0.0.0'), port=int(os.getenv('APP_PORT', 23023)),
            threaded=True, ssl_context=('cert.pem', 'key.pem'), use_reloader=False)
