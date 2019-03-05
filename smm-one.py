#!/usr/bin/env python3
# import ast
# import math
import hashlib
import os
import html
# import random
# import re
# import string
# import threading
from datetime import datetime, timedelta
# from time import sleep

import bcrypt
import requests
# from dotenv import load_dotenv
# from MySQLdb._exceptions import DataError
import whoosh.fields
# from jinja2 import Environment, FileSystemLoader
from werkzeug.contrib.fixers import ProxyFix
from email_validator import validate_email  # , EmailNotValidError

# import flask
from flask import Flask, render_template, request, redirect, url_for, flash, abort  # , json, make_response
# from flask import render_template_string, send_from_directory
from flask.json import jsonify
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
# from sqlalchemy import asc
# from sqlalchemy import desc
from flask_session import Session
# from flask_mail import Message
from flask_mail_sendgrid import MailSendGrid

from flask_whooshee import Whooshee, AbstractWhoosheer
from whoosh.index import LockError

basedir = os.path.abspath(os.path.dirname(__file__))
# TODO: move to configparser (https://hackernoon.com/4-ways-to-manage-the-configuration-in-python-4623049e841b)
# load_dotenv(os.path.join(basedir, 'settings.cfg'))

app = Flask(__name__)
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
app.wsgi_app = ProxyFix(app.wsgi_app)
app.config['APP_NAME'] = '1-SMM'
app.config['VERSION'] = '1.3.6'
app.config['SERVER_NAME'] = os.getenv('APP_DOMAIN')
app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY', '7-DEV_MODE_KEY-7')
app.config['SESSION_TYPE'] = 'redis'
# db_local = 'sqlite:///' + os.path.join(os.path.join(basedir, 'db'), 'main.db')
# db_link = f"mysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}?charset=utf8mb4"
# db_link = 'mysql://smm_one:y3./}:dKN522T>fT@localhost/smm_one?charset=utf8mb4'
db_link = 'mysql://smm_one:gJT^n<{Y72:}@localhost/smm_one?charset=utf8mb4'
app.config['SQLALCHEMY_DATABASE_URI'] = db_link
app.config['SQLALCHEMY_MIGRATE_REPO'] = os.path.join(basedir, 'db_repository')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.testing = True
app.url_map.strict_slashes = False
login_manager = LoginManager(app)
login_manager.login_view = "users.login"
sess = Session(app)
db = SQLAlchemy(app)
mail = MailSendGrid()
whooshee = Whooshee(app)


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


@app.template_filter('md5')
def md5_filter(s):
    return hashlib.md5(s.encode('utf-8')).hexdigest()


@app.template_filter('wurl')
def wbr_url_filter(s):
    s = html.escape(s)
    wbr_pos = s.find('/', s.find('/') + 2) + 1
    slink = s[:wbr_pos] + "<wbr>" + s[wbr_pos:]
    return f'<a href="{s}" target="_blank">{slink}</a>'
    # return [s[:wbr_pos], s[wbr_pos:]]


@app.template_filter('country')
def get_user_country(ip):
    return requests.get('http://ip-api.com/json/' + ip).json()['countryCode']


class Settings(db.Model):
    __tablename__ = 'settings'
    key = db.Column('key', db.String(24), primary_key=True, unique=True, nullable=False)
    value = db.Column('value', db.Text)

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __repr__(self):
        return "'%s': '%s'" % (self.key, self.value)


@whooshee.register_model('id', 'email')
class Users(db.Model):
    __tablename__ = "users"
    id = db.Column('id', db.Integer, primary_key=True)
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
        return '<User(id=%s, email=%s, balance=%s)>' % (self.id, self.email, self.balance)


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


class Types(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    short_name = db.Column(db.String(255))
    link = db.Column(db.String(255), default='https://')
    ico = db.Column(db.UnicodeText)
    status = db.Column(db.Integer, default=1)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "<Type(id='%s', name='%s')>" % (self.id, self.name)


class Services(db.Model):
    __tablename__ = 'services'
    id = db.Column('id', db.Integer, unique=True, nullable=False, primary_key=True, index=True)
    s_type = db.Column('s_type', db.String(12), default='manual')
    s_id = db.Column('s_id', db.Integer, default=0)
    name = db.Column('name', db.UnicodeText, nullable=False)
    title = db.Column('title', db.String(128), default=name)
    desc = db.Column('desc', db.String(1000), default='Описание отсутствует')
    price = db.Column('price', db.Float, default=0)
    min = db.Column('min', db.String(12), default='0')
    max = db.Column('max', db.String(12), default='999999999')
    state = db.Column('state', db.Integer, default=1)
    type = db.Column('type', db.Integer, default=0)
    country = db.Column('country', db.Integer, default=0)
    city = db.Column('city', db.Integer, default=0)
    age = db.Column('age', db.Integer, default=0)
    sex = db.Column('sex', db.Integer, default=0)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "<Service(title='%s', desc='%s', price='%s', state='%s', s_type='%s', s_id='%s', id='%s', type='%s')>" % (
            self.title, self.desc, self.price, self.state, self.s_type, self.s_id, self.id, self.type)


@whooshee.register_model('id', 'link', 'comment', 'country', 'city')
class Tasks(db.Model):
    __tablename__ = 'tasks'
    id = db.Column('id', db.Integer, unique=True, nullable=False, primary_key=True, index=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey('users.id'), nullable=False)
    # user = db.relationship('Users', backref=db.backref('entries'))
    user = db.relationship('Users', lazy=True)
    service_id = db.Column('service_id', db.String(20))
    task_id = db.Column('task_id', db.Integer, db.ForeignKey('services.id'))
    task = db.relationship('Services', lazy=True)
    s_type = db.Column('s_type', db.String(20), nullable=False)
    # TODO: Data too long for column 'link'
    link = db.Column('link', db.String(255))
    quantity = db.Column('quantity', db.String(48))
    amount = db.Column('amount', db.Float)
    status = db.Column('status', db.Integer, default=0)
    # 0 - Обработка / 1 - В работе / 2 - Выполнен / 3 - Отменен
    date = db.Column('date', db.DateTime)
    country = db.Column('country', db.String(255), default='-')
    city = db.Column('city', db.String(255), default='-')
    age = db.Column('age', db.String(255), default='-')
    sex = db.Column('sex', db.String(255), default='-')
    comment = db.Column('comment', db.String(1000), default='-')

    def __init__(self, user_id, s_type, task_id, link='', quantity='', amount=''):
        self.user_id = user_id
        self.s_type = s_type
        self.task_id = task_id
        self.link = link
        self.quantity = quantity
        self.amount = amount
        self.date = datetime.now()

    def __repr__(self):
        return "<Task(user_id='%s', service_id='%s', task_id='%s', s_type='%s', link='%s', quantity='%s', status='%s')>" % (
            self.user_id, self.service_id, self.task_id, self.s_type, self.link, self.quantity, self.status)


@whooshee.register_whoosheer
class TaskUserWhoosheer(AbstractWhoosheer):
    # create schema, the unique attribute must be in form of
    # model.__name__.lower() + '_' + 'id' (name of model primary key)
    schema = whoosh.fields.Schema(
        tasks_id=whoosh.fields.NUMERIC(stored=True, unique=True),
        user_id=whoosh.fields.NUMERIC(stored=True),
        email=whoosh.fields.TEXT(),
        link=whoosh.fields.TEXT(),
        comment=whoosh.fields.TEXT())

    # don't forget to list the included models
    models = [Users, Tasks]

    # create insert_* and update_* methods for all models
    # if you have camel case names like FooBar,
    # just lowercase them: insert_foobar, update_foobar
    @classmethod
    def update_users(cls, writer, users):
        pass  # TODO: update all users entries

    @classmethod
    def update_tasks(cls, writer, tasks):
        writer.update_document(tasks_id=tasks.id,
                               user_id=tasks.user.id,
                               email=tasks.user.email,
                               link=tasks.link,
                               comment=tasks.comment)

    # @classmethod
    # def insert_users(cls, writer, users):
    #     pass  # nothing, user doesn't have entries yet
    #
    # @classmethod
    # def insert_tasks(cls, writer, tasks):
    #     writer.add_document(tasks_id=tasks.id,
    #                         user_id=tasks.user.id,
    #                         email=tasks.user.email,
    #                         link=tasks.link,
    #                         comment=tasks.comment)
    #
    # @classmethod
    # def delete_users(cls, writer, users):
    #     pass  # TODO: delete all users entries
    #
    # @classmethod
    # def delete_tasks(cls, writer, tasks):
    #     writer.delete_by_term('tasks_id', tasks.id)


@app.template_filter('md5')
def md5_filter(s):
    return hashlib.md5(s.encode('utf-8')).hexdigest()


@app.template_filter('wurl')
def wbr_url_filter(s):
    s = html.escape(s)
    wbr_pos = s.find('/', s.find('/') + 2) + 1
    slink = s[:wbr_pos] + "<wbr>" + s[wbr_pos:]
    return f'<a href="{s}" target="_blank">{slink}</a>'
    # return [s[:wbr_pos], s[wbr_pos:]]


@app.route('/')
def index():
    tasks = Tasks.query.filter_by(user_id=current_user.id).all() if current_user.is_anonymous is not True else None
    # tasks = Tasks.query.order_by(asc(tasks.sid))
    # u = Users.query.whooshee_search('admin').order_by(Users.id.desc()).all()
    return render_template('index.html', tasks=tasks)


@app.route('/page/<section>')
def info_pages(section):
    return render_template('page/' + section + '.html')


@app.route('/admin/<section>')
@login_required
def admin_pages(section):
    if current_user.status == 7:
        tasks = Tasks.query.filter_by(s_type='manual') if section == 'tasks' else ''
        users = Users.query.all() if section == 'tasks' or 'users' else ''
        return render_template('admin/' + section + '.html', tasks=tasks, users=users)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET' or current_user.is_authenticated:
        return redirect(url_for('index'))
    email = None
    password = str.encode(request.form['password'])
    try:
        v = validate_email(request.form['email'])  # validate and get info
        email = v["email"]  # replace with normalized form
    except Exception as e:
        flash(error_ru(e), 'error')
        # return jsonify({'response': 0, 'error': str(e) + ' (' + r['text'][0] + ')'}), 400
    if email is None:
        pass
    elif len(password) < 6:
        flash('Пароль должен состоять минимум из 6 символов', 'error')
    elif Users.query.filter_by(email=email).first():
        flash('Этот email уже зарегистрирован', 'error')
    else:
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        user = Users(email, hashed_password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash(f'Зарегистрирован пользователь {user.email}')
        # return jsonify({'response': 1})
    # return redirect(url_for('index'))
    return jsonify({'response': 1})


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
    # return redirect(request.args.get('next') or url_for('index'))
    return jsonify({'response': 1})


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


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


@app.route('/ajax/tasks/', methods=['GET'])
@login_required
def load_tasks():
    if current_user.status == 7:
        # tasks = Tasks.query.filter_by(status=status).order_by(Tasks.id.desc()).offset(0).limit(0)
        # tasks = Tasks.query.filter_by(status=request.args.get("status"))
        q = request.args.get('query')
        q = q[:q.find('@')] if '@' in q else q
        if str.isdigit(q):
            tasks = Tasks.query.filter_by(id=int(q))
        elif q:
            try:
                # tasks = Tasks.query.whooshee_search(q, order_by_relevance=-1)
                tasks = Tasks.query.whooshee_search(q, whoosheer=TaskUserWhoosheer).order_by(Tasks.id.desc())
                # tasks = Tasks.query.join(Users).whooshee_search(q).order_by(Tasks.id.desc())
                # print(Tasks.query.join(Users).whooshee_search(q).order_by(Tasks.id.desc()))
            except Exception as e:
                return render_template('tasks_list.html', error=error_ru(e))
        else:
            tasks = Tasks.query.filter_by(status=request.args.get("status"))
        return render_template('tasks_list.html', tasks=tasks)
    return abort(403)


@app.route('/ajax/users/', methods=['GET'])
@login_required
def load_users():
    if current_user.status == 7:
        q = request.args.get('query')
        q = q[:q.find('@')] if '@' in q else q
        if str.isdigit(q):
            users = Users.query.filter_by(id=int(q))
        elif q:
            try:
                users = Users.query.whooshee_search(q)
            except Exception as e:
                return error_ru(e)
        else:
            users = Users.query
        return render_template('users_list.html', users=users)
    return abort(403)


@app.route('/ajax/save/<section>', methods=['POST'])
@login_required
def save_settings(section):
    if current_user.status == 7:
        if section == 'settings-main':
            for i in request.json.items():
                Settings.query.filter_by(key=i[0]).first().value = i[1]
        elif section == 'settings-services':
            for i in request.json:
                service = Services.query.filter_by(id=i['id'])
                service = Services(str(i['title'])) if i['action'] == 'add' else service.first() if i[
                                                                                                        'action'] == 'upd' else service
                service.title = i['title']
                service.desc = i['desc']
                service.price = i['price']
                service.state = i['state']
                service.country = i['param-country']
                service.city = i['param-city']
                service.age = i['param-age']
                service.sex = i['param-sex']
                service.type = i['type']
                service.min = i['min']
                service.max = i['max']
                service.delete() if i['action'] == 'rm' else db.session.add(service)
            flash('Сохранено успешно')
        elif section == 'state':
            # TODO: нулевая стоимость заказа для отмененных
            task = Tasks.query.filter_by(id=request.json['id']).first()
            task.status = request.json['state']
            if request.json['state'] == '3':
                Users.query.filter_by(id=task.user_id).first().balance += task.amount
                task.amount = 0
                # current_user.balance += task.amount
            elif request.json['state'] == '666':
                db.session.delete(task)
        elif section == 'settings-users':
            for i in request.json:
                user = Users.query.filter_by(id=i['id']).first()
                user.email = i['email']
                user.balance = i['balance']
        elif section == 'user':
            user = Users.query.filter_by(id=request.json['uid']).first()
            # TODO: если что-то не менялось - не менять
            try:
                v = validate_email(request.json['email'])  # validate and get info
                user.email = v["email"]  # replace with normalized form
            except Exception as e:
                return jsonify({'response': 0, 'error': error_ru(e)}), 500
            user.balance = request.json['balance']
            if request.json['password']:
                user.password = bcrypt.hashpw(str.encode(request.json['password']), bcrypt.gensalt())
                # user.status = -1
                # user.is_active = False
                # user.is_authenticated = False
        db.session.commit()
        init_settings()
        return jsonify({'response': 1})
    return abort(403)


@app.route('/ajax/new-task', methods=['POST'])
@login_required
def add_task():
    try:
        service = Services.query.filter_by(id=request.json['tid']).first()
        amount = service.price / 1000 * float(request.json['quantity'])
        amount = service.price if request.json['tid'] == '210' else amount
        task = Tasks(current_user.id, service.s_type, int(request.json['tid']), html.escape(request.json['link']),
                     html.escape(request.json['quantity']), amount)
    except ValueError:
        # return jsonify({'response': -1, 'msg': 'Неверное значение одного из параметров'}), 400
        return jsonify({'response': 0, 'error_code': 1, 'msg': 'Неверное значение одного из параметров'}), 400
    except Exception as e:
        return jsonify({'response': 0, 'error_code': 666, 'msg': 'Неизвестная ошибка: ' + e}), 400
    if int(request.json['quantity']) < int(service.min) or int(request.json['quantity']) > int(service.max):
        return jsonify({'response': 0, 'error_code': 3, 'msg': 'Указан недопустимый объем заказа'}), 400
    elif amount < 0:
        return jsonify({'response': 0, 'error_code': 2, 'msg': 'Сумма заказа не может быть отрицательным =('}), 400
    elif (request.json['link'].find('http://') == 0 or request.json['link'].find('https://') == 0) is False:
        return jsonify({'response': 0, 'error_code': 4, 'msg': 'Ссылка должна начинаться с http:// или https://'}), 400
    elif amount > current_user.balance:
        return jsonify({'response': 0, 'error_code': 5, 'msg': 'Недостаточно средств на Вашем счету'}), 400
    elif (service.id == 93 or service.id == 104) and int(html.escape(request.json['quantity'])) % 100:
        return jsonify({'response': 0, 'error_code': 6, 'msg': 'Количество должно быть кратно 100'}), 400
    elif service.s_type == 'nakrutka':
        # https://smm.nakrutka.by/api/?key=6d123fc8e9cb840f64164e82dad3c27d&action=create&service=3&quantity=200&link=https://www.instagram.com/jaholper/
        url = 'https://smm.nakrutka.by/api/?key=' + Settings.query.filter_by(key='nakrutka_apikey').first().value
        url += '&action=create' + '&service=' + str(service.s_id) + '&quantity=' + str(
            request.json['quantity']) + '&link=' + str(request.json['link'])
        r = requests.get(url).json()
        if 'Error' in r:
            return jsonify({'response': 0, 'msg': r['Error']})
        elif 'order' in r:
            task.service_id = r['order']
            task.status = 1
    elif service.s_type == 'bigsmm':
        # http://bigsmm.ru/api/?method=add_order&api_key=586503944eff44fdb212486c28761793&service_id=11&variation_id=54&order_link=instagram.com/test/
        # {"errorcode":"0","msg":"Успешно","order_id":"7307"}
        url = 'http://bigsmm.ru/api/?method=add_order&api_key=' + Settings.query.filter_by(
            key='bigsmm_apikey').first().value
        url += '&service_id=' + str(service.s_id) + '&quantity=' + str(request.json['quantity']) + '&order_link=' + str(
            request.json['link'])
        r = requests.get(url).json()
        if 'order_id' in r:
            task.service_id = r['order_id']
            task.status = 1
        elif ('errorcode' in r) and (r['errorcode'] > 0):
            return jsonify({'response': 0, 'msg': r['msg']})
    elif service.s_type == 'manual':
        task.quantity = html.escape(request.json['quantity'])
        task.link = html.escape(request.json['link'])
        task.country = html.escape(request.json['country'])
        task.city = html.escape(request.json['city'])
        task.age = html.escape(request.json['age'])
        task.sex = html.escape(request.json['sex'])
        task.comment = html.escape(request.json['comment'])
    current_user.balance -= amount
    db.session.add(task)
    db.session.commit()
    init_settings()
    return jsonify({'response': 1})


def error_ru(text):
    d = {
        'key': 'trnsl.1.1.20150724T160237Z.3773b6e8841caa1b.3fe37f6c20f79391bd69ff57129c5f118fd56d6a',
        'text': str(text),
        'lang': 'en-ru'
    }
    r = requests.get('https://translate.yandex.net/api/v1.5/tr.json/translate', data=d).json()
    return r['text'][0]


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
    app.config['SERVICES'] = Services.query.all()
    # app.config['MAIL_SENDGRID_API_KEY'] = Settings.query.filter_by(key='mailgrid_key').first().value
    # mail.init_app(app)
    # whooshee.init_app(app)
    whooshee.register_whoosheer(TaskUserWhoosheer)
    # whooshee.reindex()


if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true" or 1 == 1:
    init_settings()

if __name__ == '__main__':
    app.run(host=os.getenv('APP_IP', '0.0.0.0'), port=int(os.getenv('APP_PORT', 23033)),
            threaded=True, use_reloader=False, debug=True)
