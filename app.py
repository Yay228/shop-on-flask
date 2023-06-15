from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import re
from flask_migrate import Migrate
from sqlalchemy import func

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SECRET_KEY'] = '35af661f77853008b76aa25d99e42d8f'
db = SQLAlchemy(app)



migrate = Migrate(app, db)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def check_password_strength(password):
    """
    Проверяет сложность пароля.
    Пароль должен быть как минимум 8 символов и содержать заглавные буквы, строчные буквы и цифры.
    """
    if len(password) < 8:
        return False
    elif not re.search("[a-z]", password):
        return False
    elif not re.search("[A-Z]", password):
        return False
    elif not re.search("[0-9]", password):
        return False
    else:
        return True
    
    
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    text = db.Column(db.Text, nullable=True)
    cost = db.Column(db.Integer, nullable=False)
    genre = db.Column(db.Text(50), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/home')
@app.route('/')
def main():
    return render_template('main.html')

@app.route('/shop')
@login_required
def shop():
    shop = Post.query.all()
    return render_template('shop.html', posts=shop)

@app.route('/create', methods=['POST', 'GET'])
@login_required
def create():
    if request.method == "POST":
        title = request.form['title']
        text = request.form['text']
        cost = request.form['cost']
        genre = request.form['genre']
        # проверяем, что поля title, text и cost не пустые
        if not title or not text or not cost:
            flash('Fields cannot be empty!')
            return redirect(request.url)


        post = Post(title=title, cost=cost, text=text, genre=genre)

        try:
            db.session.add(post)
            db.session.commit()
            return redirect('/')
        except:
            return "An error occurred while adding!"
    else:
        return render_template('create.html')
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user is not None and user.check_password(password) == True:
            login_user(user)
            return redirect(url_for('main'))
        # else:
            # return jsonify({"message": "Invalid username or password."})
    return render_template('login.html')
 
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user:
            flash("Такой логин уже существует")
            return redirect(url_for('register'))
    
        if not check_password_strength(password):
            flash('Password is not strong enough. It should be at least 8 characters long, include uppercase, lowercase letters and numbers.')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main'))

@app.route('/search', methods=['GET', 'POST'])
def search():
    all1 = Post.query.all()
    search = request.args.get("search").lower()
    if search:
        search = search.lower()
    result = Post.query.filter(func.lower(Post.title).like(f"%{search}%")).all()
    return render_template("search.html", result=result, all1 = all1)


@app.route('/buy/<int:id>')
def buy(id):
    post = Post.query.get(id)
    return render_template("buy.html", id = id, post = post)