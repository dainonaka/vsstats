from flask import Flask, request, Response, abort, render_template, g, redirect, url_for
from hamlish_jinja import HamlishExtension
from sqlalchemy.orm import synonym
from werkzeug import ImmutableDict, check_password_hash, generate_password_hash
import os
import sqlite3
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from collections import defaultdict
from datetime import datetime


class FlaskWithHamlish(Flask):
    jinja_options = ImmutableDict(
        extensions=[HamlishExtension]
    )
app = FlaskWithHamlish(__name__)

login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = "secret"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login'))


db_uri = db_uri = os.environ.get('DATABASE_URL') or "sqlite:///" + os.path.join(app.root_path, 'vsstats.db') 

app.config['SQLALCHEMY_DATABASE_URI'] = db_uri 
db = SQLAlchemy(app) 

class Entry(db.Model): 
    __tablename__ = "records" 
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user = db.Column(db.Integer, nullable=False)
    win = db.Column(db.Integer) 
    opponent = db.Column(db.VARCHAR(10)) 
    comment = db.Column(db.VARCHAR(20))
    date = db.Column(db.DATETIME, nullable=False) 

class User(UserMixin, db.Model): 
    __tablename__ = "users" 
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.VARCHAR(10), nullable=False, unique=True)
    _password = db.Column(db.VARCHAR(20), nullable=False) 
    date = db.Column(db.DATETIME, nullable=False) 

    def _get_password(self):
        return self._password

    def _set_password(self, password):
        if password:
            password = password.strip()
        self._password = generate_password_hash(password)
    password_descriptor = property(_get_password, _set_password)
    password = synonym('_password', descriptor=password_descriptor)

    # フォームで送信されたパスワードの検証
    def check_password(self, password):
        password = password.strip()
        if not password:
            return False
        return check_password_hash(self.password, password)

    # 認証処理
    @classmethod
    def auth(cls, query, name, password):
        user = query(cls).filter(cls.name==name).first()
        if user is None:
            return None, False
        return user, user.check_password(password)


def connect_db():
    db_path = os.path.join(app.root_path, 'vsstats.db')
    rv = sqlite3.connect(db_path)
    rv.row_factory = sqlite3.Row
    return rv

def get_db():
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db

@app.route('/')
@login_required
def index():
    entries = get_db().execute('select * from records inner join users on records.user = users.id order by id desc limit 10').fetchall() # 追加
    return render_template('index.haml', entries=entries, current_user=current_user) # 変更

@app.route('/post', methods=['POST'])
@login_required
def add_entry():
    entry = Entry()
    entry.user = current_user.id
    entry.win = request.form["win"]
    entry.opponent = request.form['opponent']
    entry.comment = request.form['comment']
    entry.date = datetime.now()
    db.session.add(entry)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/createuser', methods=["GET", "POST"])
def createuser():
    if(request.method == "POST"):
        # ユーザー作成
        if all([request.form["username"],
        request.form["password"],
        request.form["password"] == request.form["password_validation"]
        ]):
            user = User()
            user.name = request.form["username"]
            user.password = request.form["password"]
            user.date = datetime.now()
            db.session.add(user)
            db.session.commit()
            return Response(f'''
            account created!<br />
            <a href="{url_for('index')}">index</a><br />
            <a href="{url_for('logout')}">logout</a>
            ''')
        else:
            return abort(401)
    else:
        return render_template("createuser.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    if(request.method == "POST"):
        # ユーザーチェック
        user, authenticated = User.auth(db.session.query, request.form["username"], request.form["password"])
        if authenticated:
            login_user(user, remember=True)
            return redirect(url_for('index'))
        else:
            return abort(401)
    else:
        return render_template("login.html")

# ログアウトパス
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return Response('''
    ログアウトしました<br />
    <a href="/login">ログイン</a>
    ''')


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

if __name__ == "__main__":
    app.run()
