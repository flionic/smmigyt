#!/usr/bin/env python3.7
import hashlib
import os
import sys
import html
import secrets
from datetime import datetime

import bcrypt
import requests
# from dotenv import load_dotenv
import whoosh.fields
from sqlalchemy import extract
from werkzeug.contrib.fixers import ProxyFix
from email_validator import validate_email

from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask.json import jsonify
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_mail import Message
from flask_mail_sendgrid import MailSendGrid

from flask_whooshee import Whooshee, AbstractWhoosheer
from whoosh.index import LockError

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, instance_relative_config=True)
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
app.wsgi_app = ProxyFix(app.wsgi_app)
app.config['APP_NAME'] = 'smmone'
app.config['VERSION'] = '1.5.2'
app.config['SERVER_NAME'] = os.getenv('APP_DOMAIN')
app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY', '7-DEV_MODE_KEY-7')
app.config['SESSION_TYPE'] = 'redis'
# db_local = 'sqlite:///' + os.path.join(os.path.join(basedir, 'db'), 'main.db')
# db_link = f"mysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}?charset=utf8mb4"
# TODO: move to configparser (https://hackernoon.com/4-ways-to-manage-the-configuration-in-python-4623049e841b)
# load_dotenv(os.path.join(basedir, 'settings.cfg'))
db_link = 'mysql://smm_one:gJT^n<{Y72:}@localhost/smm_one?charset=utf8mb4'
# db_link = 'mysql://sersmm:S6KHk95(=7K9@localhost/sersmm?charset=utf8mb4'
app.config['SQLALCHEMY_DATABASE_URI'] = db_link
app.config['SQLALCHEMY_MIGRATE_REPO'] = os.path.join(basedir, 'db_repository')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.testing = True
app.url_map.strict_slashes = False
login_manager = LoginManager(app)
login_manager.login_view = "users.login"
sess = Session(app)
db = SQLAlchemy(app)
# mail = MailSendGrid()
app.config['MAIL_SENDGRID_API_KEY'] = ''
mail = MailSendGrid(app)
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


@app.template_filter('country')
def get_user_country(ip):
    return requests.get('http://ip-api.com/json/' + ip).json()['countryCode']


@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


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
    status = db.Column('status', db.Integer, nullable=False, default=0)  # 0 - locked, 1 - active, 6 - banned, 7 - admin
    signup_date = db.Column('signup_date', db.DateTime)
    last_login = db.Column('last_login', db.DateTime)
    token = db.Column('token', db.UnicodeText)
    api_token = db.Column('api_token', db.UnicodeText)
    reseller = db.Column('reseller', db.Integer)

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

    def make_token(self):
        return str.encode(str(self.token))

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

    # TODO: refactoring me
    def __repr__(self):
        return "<Payment(user_id='%s', ik_inv_id='%s', ik_pm_no='%s', ik_state='%s')>" % (self.user_id, self.ik_inv_id, self.ik_pm_no, self.ik_state)


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
    price_resellers = db.Column('price_resellers', db.Float, default=0)
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

    # TODO: refactoring me
    def __repr__(self):
        return "<Service(title='%s', desc='%s', price='%s', state='%s', s_type='%s', s_id='%s', id='%s', type='%s')>" % (
        self.title, self.desc, self.price, self.state, self.s_type, self.s_id, self.id, self.type)


# @whooshee.register_model('link', 'comment', 'country', 'city')
class Tasks(db.Model):
    __tablename__ = 'tasks'
    id = db.Column('id', db.Integer, unique=True, nullable=False, primary_key=True, index=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('Users', lazy=True)
    service_id = db.Column('service_id', db.String(20))
    task_id = db.Column('task_id', db.Integer, db.ForeignKey('services.id'))
    service = db.relationship('Services', lazy=True)
    s_type = db.Column('s_type', db.String(20), nullable=False)
    # TODO: Data too long for column 'link'
    link = db.Column('link', db.String(255))
    quantity = db.Column('quantity', db.String(48))
    amount = db.Column('amount', db.Float)
    status = db.Column('status', db.Integer, default=0)  # 0 - Обработка, 1 - В работе, 2 - Выполнен, 3 - Отменен
    date = db.Column('date', db.DateTime)
    country = db.Column('country', db.String(255), default='-')
    city = db.Column('city', db.String(255), default='-')
    age = db.Column('age', db.String(255), default='-')
    sex = db.Column('sex', db.String(255), default='-')
    comment = db.Column('comment', db.String(1000), default='-')
    cons = db.Column(db.String(1000), default='0')
    adm_comment = db.Column(db.String(1000), default='')

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
    # TODO: refactoring me
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


@app.route('/')
def index():
    # TODO: подгружать сервисы аджаксом
    tasks = None if current_user.is_anonymous is True else Tasks.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', tasks=tasks, services=Services.query)


@app.route('/info/<page>')
def info_pages(page):
    return render_template('pages/info.html', data=['Описание', page, 'Конец'])


@app.route('/pages/<section>')
def main_pages(section):
    return render_template('pages/' + section + '.html')


@app.route('/admin/<section>')
@login_required
def admin_pages(section):
    # TODO: make admin handler
    if current_user.status == 7:
        services = Services.query if section == 'settings' else None
        return render_template('admin/' + section + '.html', services=services)
    else:
        flash('Упс, этот раздел недоступен для Вас', 'error')
        return redirect(url_for('index'))


@app.route('/wordpess/vivian')
def photo_test():
    return jsonify({'response': 'ok', 'code': "get_template_part('template', 'blog')"})


@app.route('/signup', methods=['POST'])
def signup():
    email = request.form['email']
    password = str.encode(request.form['password'])
    if current_user.is_authenticated:
        flash('Вы уже авторизированы', 'error')
    elif Users.query.filter_by(email=email).first():
        flash('Этот email уже зарегистрирован', 'error')
    elif len(password) < 6:
        flash('Пароль должен состоять минимум из 6 символов', 'error')
    else:
        try:
            email = validate_email(email)["email"]
        except Exception as e:
            flash(en_to_ru(e), 'error')
        else:
            hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
            user = Users(email, hashed_password)
            user.last_login = datetime.now()
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash(f'Добро пожаловать, {user.email}!')
    return jsonify({'response': 1})


@app.route('/login', methods=['POST'])
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


@app.route('/reset', methods=['GET', 'POST'])
def reset_pass():
    if request.form.get('email'):
        token = secrets.token_hex(16)
        user = Users.query.filter_by(email=request.form['email']).first()
        if user:
            user.token = token
            db.session.commit()
            msg = Message("Восстановление пароля", sender=Settings.query.filter_by(key='email').first().value, recipients=[user.email])
            msg.html = f"<h1>Сброс пароля</h1><br>" \
                       f"Вы запрашивали <b>сброс пароля</b> на сайте. <a href=https://{ app.config['APP_DOMAIN'] }/reset?token={ token }>Подтвердите это действие</a>."
            mail.send(msg)
            flash('На Ваш email было отправлено письмо с ссылкой для сброса пароля')
        else:
            flash('Пользователь с таким email не зарегистрирован', 'error')
    elif 'token' in request.args:
        user = Users.query.filter_by(token=request.args.get('token')).first()
        if user:
            user.token = None
            login_user(user)
            db.session.commit()
            return redirect(url_for('index') + '?reset=1')
        else:
            flash('Недействительная ссылка для сброса пароля', 'error')
    else:
        flash('Вы не ввели email адрес', 'error')
    if request.method == 'GET':
        return redirect(url_for('index'))
    else:
        return jsonify({'response': 1})


@app.route('/change-pass', methods=['POST'])
@login_required
def change_password():
    password = str.encode(request.form.get('password'))
    password_two = str.encode(request.form.get('password_two'))
    if password != password_two:
        flash('Пароли не совпадают', 'error')
    elif len(password) < 6:
        flash('Пароль должен состоять минимум из 6 символов', 'error')
    else:
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        user = Users.query.filter_by(id=current_user.id).first()
        user.password = hashed_password
        db.session.commit()
        flash('Пароль успешно изменен')
    return jsonify({"response": 1})


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
            ik_r = requests.get(ik_url + 'co-invoice/' + request.form.get('ik_inv_id'), headers=headers, auth=auth).json()
            # {'status': 'error', 'code': 4, 'data': {'innerCode': 0}, 'message': 'Auth: api not enabled for current user'}
            inv.ik_state = ik_r['data']['state']
            if inv.ik_state == '7':
                inv.ik_inv_prc = ik_r['data']['processed']
                inv.ik_am = float(ik_r['data']['coAmount'])
                inv.ik_cur = ik_r['data']['currencyCodeChar']
                inv.total_am = inv.ik_am
                if ik_r['data']['currencyId'] != 40:
                    ik_curr = requests.get(ik_url + 'currency/' + str(ik_r['data']['currencyId']), headers=headers, auth=auth).json()
                    inv.total_am *= float(ik_curr['data'][inv.ik_cur]['RUB']['out'])
                user.balance = round(user.balance + inv.total_am, 2)
                print(f'Added {inv.ik_am} {inv.ik_cur} to {user.email}')
        db.session.commit()
        return jsonify('OK'), 200
    return redirect(url_for('index'))


@app.route('/ajax/get/<section>', methods=['GET'])
@login_required
def load_data(section):
    """
    args: status, page, query
    :param section: users or tasks
    :return: list of target users or tasks
    """
    if current_user.status == 7:
        data = (Users if section == 'users' else Tasks).query
        if section == 'crm':
            data = Tasks.query.order_by(Tasks.id.desc()).filter(extract('month', Tasks.date) == request.args.get('month'))
        q = request.args.get('query')
        if str.isdigit(q):
            data = data.filter_by(id=int(q))
        elif q:
            try:
                q = q[:q.find('@')] if '@' in q[1:] else q.replace('@', '')  # removing unsearchable @
                # tasks = Tasks.query.join(Users).whooshee_search(q, order_by_relevance=-1).order_by(Tasks.id.desc())
                data = data.whooshee_search(q) if section == 'users' else data.whooshee_search(q, whoosheer=TaskUserWhoosheer)
            except Exception as e:
                return en_to_ru(e)
        elif request.args.get('status'):
            data = data.filter_by(status=request.args.get("status"))
        return render_template(section + '_list.html', data=data)
    return abort(403)


@app.route('/ajax/save/<section>', methods=['POST'])
@login_required
def save_settings(section):
    # TODO: refactoring this
    if current_user.status == 7:
        if section == 'settings-main':
            for i in request.json.items():
                Settings.query.filter_by(key=i[0]).first().value = i[1]
                init_settings()
        elif section == 'settings-services':
            for i in request.json:
                service = Services.query.filter_by(id=i['id'])
                service = Services(str(i['title'])) if i['action'] == 'add' else service.first() if i['action'] == 'upd' else service
                service.title = i['title']
                service.desc = i['desc']
                service.price = i['price']
                service.price_resellers = i['price-resellers']
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
            task = Tasks.query.filter_by(id=request.json['id']).first()
            task.status = request.json['state']
            if request.json['state'] == '3':
                user = Users.query.filter_by(id=task.user_id).first()
                user.balance += task.amount
                task.amount = 0
                task.comment = 'АДМИНИСТРАЦИЯ: ' + request.json['msg']
                msg = Message("Ваш заказ отменен", sender=Settings.query.filter_by(key='email').first().value, recipients=[user.email])
                msg.html = f"Причина отмены: { request.json['msg'] }"
                mail.send(msg)
            elif request.json['state'] == '666':
                db.session.delete(task)
        elif section == 'settings-users':
            for i in request.json:
                user = Users.query.filter_by(id=i['id']).first()
                user.email = i['email']
                user.balance = i['balance']
        elif section == 'user':
            user = Users.query.filter_by(id=request.json['uid']).first()
            if request.json['email'] != user.email:
                try:
                    user.email = validate_email(request.json['email'])["email"]
                except Exception as e:
                    return jsonify({'response': 0, 'error': en_to_ru(e)}), 500
            if request.json['balance'] != user.balance:
                user.balance = request.json['balance']
            if request.json['password']:
                # TODO: разлогин после смены пароля
                user.password = bcrypt.hashpw(str.encode(request.json['password']), bcrypt.gensalt())
            if 'reseller' in request.json:
                user.reseller = 1
            else:
                user.reseller = 0
        elif section == 'gen-token':
            user = Users.query.filter_by(id=current_user.id).first()
            user.api_token = secrets.token_hex(16)
        elif section == 'crm_cons':
            task = Tasks.query.filter_by(id=int(request.json['task_id'])).first()
            task.cons = float(request.json['cons'])
        elif section == 'crm_comment':
            task = Tasks.query.filter_by(id=int(request.json['task_id'])).first()
            task.adm_comment = request.json['adm-comment']
        db.session.commit()
        return jsonify({'response': 1})
    elif section == 'gen-token':
        user = Users.query.filter_by(id=current_user.id).first()
        user.api_token = secrets.token_hex(16)
        db.session.commit()
        return jsonify({'response': 1})
    return abort(403)


@app.route('/api/<section>', methods=['GET'])
def app_api(section):
    user = Users.query.filter_by(api_token=request.args.get('token')).first()
    if user:
        if section == 'add':
            if request.args.get('quantity') and request.args.get('link') and request.args.get('id'):
                try:
                    service = Services.query.filter_by(id=request.args.get('id')).first()
                    price = service.price_resellers if user.reseller == 1 else service.price
                    amount = price / 1000 * float(request.args.get('quantity'))
                    amount = price if request.args.get('id') == '210' else amount
                    task = Tasks(user.id, service.s_type, int(request.args.get('id')), html.escape(request.args.get('link')), html.escape(request.args.get('quantity')), amount)
                except ValueError:
                    return jsonify({'response': {'error': 'Неверное значение одного из параметров'}}), 400
                except Exception as e:
                    return jsonify({'response': {'error': 'Неизвестная ошибка: ' + en_to_ru(str(e))}}), 400
                if int(request.args.get('quantity')) < int(service.min) or int(request.args.get('quantity')) > int(service.max):
                    return jsonify({'response': {'error': 'Указан недопустимый объем заказа'}}), 400
                elif amount < 0:
                    return jsonify({'response': {'error': 'Сумма заказа не может быть отрицательным =('}}), 400
                elif (request.args.get('link').find('http://') == 0 or request.args.get('link').find('https://') == 0) is False:
                    return jsonify({'response': {'error': 'Ссылка должна начинаться с http:// или https://'}}), 400
                elif amount > user.balance:
                    return jsonify({'response': {'error': 'Недостаточно средств на Вашем счету'}}), 400
                elif (service.id == 93 or service.id == 104) and int(html.escape(request.args.get('quantity'))) % 100:
                    return jsonify({'response': {'error': 'Количество должно быть кратно 100'}}), 400
                elif service.s_type == 'manual':
                    task.quantity = html.escape(request.args.get('quantity'))
                    task.link = html.escape(request.args.get('link'))
                    task.comment = html.escape(request.args.get('comment')) if request.args.get('comment') else ''
                current_user.balance -= amount
                db.session.add(task)
                try:
                    db.session.commit()
                except LockError:
                    return jsonify({'response': 0, 'error': 'В данный момент идет переиндексация базы, повторите попытку через минуту'}), 503
                else:
                    return jsonify({"response": {"tid": task.id}})
            else:
                return jsonify({"response": {"error": "Отсутствует обязательный параметр"}})
        elif section == 'status':
            task = Tasks.query.filter_by(id=request.args.get('tid')).first()
            if task is None:
                return jsonify({"response": {"error": "Такой задачи не существует"}})
            if task.user_id != user.id:
                return jsonify({"response": {"error": "Эта задача была создана с другого аккаунта"}})
            return jsonify({"response": {"status": task.status}})
        else:
            return jsonify({"response": {"error": "Неизвестный запрос"}})
    else:
        return jsonify({"response": {"error": "Неверный token"}})


@app.route('/ajax/new-task', methods=['POST'])
@login_required
def add_task():
    try:
        service = Services.query.filter_by(id=request.json['tid']).first()
        price = service.price_resellers if current_user.reseller == 1 else service.price
        amount = price / 1000 * float(request.json['quantity'])
        amount = price if request.json['tid'] == '210' else amount
        task = Tasks(current_user.id, service.s_type, int(request.json['tid']), html.escape(request.json['link']), html.escape(request.json['quantity']), amount)
    except ValueError:
        return jsonify({'response': 0, 'error_code': 1, 'msg': 'Неверное значение одного из параметров'}), 400
    except Exception as e:
        return jsonify({'response': 0, 'error_code': 666, 'msg': 'Неизвестная ошибка: ' + en_to_ru(str(e))}), 400
    if int(request.json['quantity']) < int(service.min) or int(request.json['quantity']) > int(service.max):
        return jsonify({'response': 0, 'error_code': 3, 'msg': 'Указан недопустимый объем заказа'}), 400
    elif amount < 0:
        return jsonify({'response': 0, 'error_code': 2, 'msg': 'Сумма заказа не может быть отрицательным =('}), 400
    elif (request.json['link'].find('http://') == 0 or request.json['link'].find('https://') == 0) is False:
        return jsonify({'response': 0, 'error_code': 4, 'msg': 'Ссылка должна начинаться с http:// или https://'}), 400
    elif amount > current_user.balance + 1:
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
    try:
        db.session.commit()
    except LockError:
        return jsonify({'response': 0, 'msg': 'В данный момент идет переиндексация базы, повторите попытку через минуту'}), 503
    else:
        return jsonify({'response': 1})


@app.route('/ajax/system/reindex', methods=['GET', 'POST'])
@login_required
def reindex_search():
    if current_user.status == 7:
        app.config['REINDEXING'] = 1
        whooshee.reindex()
        app.config['REINDEXING'] = 0
        return jsonify({'response': 1})
    return abort(403)


def en_to_ru(text):
    try:
        d = {
            'key': app.config['YA_TRANSLATE_KEY'],
            'text': str(text),
            'lang': 'en-ru'
        }
        text = requests.get('https://translate.yandex.net/api/v1.5/tr.json/translate', data=d).json()['text'][0]
    except Exception as e:
        print(e)
    finally:
        return text


def init_settings():
    app.config['MAINTENANCE'] = 0
    app.config['APP_TITLE'] = Settings.query.filter_by(key='app_name').first().value
    app.config['APP_DOMAIN'] = Settings.query.filter_by(key='app_domain').first().value
    app.config['SERVER_NAME'] = app.config['APP_DOMAIN']
    app.config['IK_ID_CHECKOUT'] = Settings.query.filter_by(key='ik_id_checkout').first().value
    app.config['IK_ID'] = Settings.query.filter_by(key='ik_id').first().value
    app.config['IK_KEY'] = Settings.query.filter_by(key='ik_key').first().value
    app.config['NAKRUTKA_APIKEY'] = Settings.query.filter_by(key='nakrutka_apikey').first().value
    app.config['BIGSMM_APIKEY'] = Settings.query.filter_by(key='bigsmm_apikey').first().value
    # app.config['MAIL_SENDGRID_API_KEY'] = Settings.query.filter_by(key='mailgrid_key').first().value
    app.config['YA_TRANSLATE_KEY'] = Settings.query.filter_by(key='ya_translate_key').first().value

    # flask.request.headers['Host']
    # mail.init_app(app)


if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true" or 1 == 1:
    db.create_all()
    init_settings()
    whooshee.register_whoosheer(TaskUserWhoosheer)

if __name__ == '__main__':
    print('Start Flask')
    # app.run(host=os.getenv('APP_IP', '0.0.0.0'), port=int(os.getenv('APP_PORT', 23033)), threaded=True, use_reloader=False, debug=True)
    app.run(host=os.getenv('APP_IP', '0.0.0.0'), port=int(os.getenv('APP_PORT', 23038)), threaded=True, use_reloader=False, debug=True)
