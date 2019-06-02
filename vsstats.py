from flask import Flask, request, Response, abort, render_template, g, redirect, url_for
from hamlish_jinja import HamlishExtension
from sqlalchemy.orm import synonym
from sqlalchemy.sql import func
from werkzeug import ImmutableDict, check_password_hash, generate_password_hash
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from collections import defaultdict
from datetime import datetime, date


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


db_uri = os.environ.get('DATABASE_URL') # or "sqlite:///" + os.path.join(app.root_path, 'vsstats.db')

app.config['SQLALCHEMY_DATABASE_URI'] = db_uri 
db = SQLAlchemy(app) 

class Entry(db.Model): 
    __tablename__ = "records" 
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user = db.Column(db.Integer, nullable=False)
    win = db.Column(db.Integer) 
    opponent = db.Column(db.VARCHAR(10)) 
    comment = db.Column(db.VARCHAR(20))
    date = db.Column(db.DATE, nullable=False) 

class User(UserMixin, db.Model): 
    __tablename__ = "users" 
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.VARCHAR(10), nullable=False, unique=True)
    _password = db.Column(db.VARCHAR(65535), nullable=False) 
    date = db.Column(db.DATE, nullable=False) 

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

def injection_check(input):
    if not str(input).isdecimal():
        return abort(404)

@app.route('/')
@login_required
def index():
    entries = db.session.query(Entry, User).join(Entry, Entry.user==User.id).all() # 追加
    return render_template('index.haml', entries=entries, current_user=current_user) # 変更

@app.route('/post', methods=['POST'])
@login_required
def add_entry():
    entry = Entry()
    entry.user = current_user.id
    entry.win = request.form["win"]
    entry.opponent = request.form['opponent']
    entry.comment = request.form['comment']
    entry.date = date.today()
    db.session.add(entry)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/mypage/<id>')
@login_required
def mypage(id=id):
    injection_check(id)
    startmonth = date.today().replace(day=1)
    entries = db.session.query(Entry).filter(Entry.user==id).limit(100).all()
    user = db.session.query(User).filter(User.id==id).one()
    totalpoint = db.session.query(Entry.win).filter(Entry.user==id).all()
    monthpoint = db.session.query(Entry.win).filter(Entry.user==id and Entry.date>=startmonth).all()
    wincount = monthpoint.count((2,))
    losecount = monthpoint.count((1,))
    return render_template('mypage.haml',
                        entries=entries,
                        user=user,
                        current_user=current_user,
                        totalpoint=sum([point[0] for point in totalpoint]),
                        wincount=wincount,
                        losecount=losecount,
                        startmonth=startmonth)

@app.route('/edit/<id>', methods=["POST"])
@login_required
def entryedit(id):
    injection_check(id)
    if request.form["command"] == "削除":
        user_id = get_db(True).execute(f'select user from records where id = {id}').fetchall()[0]
        if user_id[0] == current_user.id:
            db.session.query(Entry).filter(Entry.id==id).delete()
            db.session.commit()
        else:
            return abort(401)
    
    return redirect(f'mypage/{current_user.id}')


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
            user.date = date.today()
            db.session.add(user)
            db.session.commit()

            user, authenticated = User.auth(db.session.query, request.form["username"], request.form["password"])

            if authenticated:
                login_user(user, remember=True)
                return redirect(url_for('index'))
            
            else:
                return redirect(url_for('login'))
                
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

if __name__ == "__main__":
    app.run()
