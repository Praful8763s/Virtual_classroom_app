from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///virtual_classroom.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Class(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    instructor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    instructor = db.relationship('User', backref=db.backref('classes', lazy=True))

class Unit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=False)
    class_obj = db.relationship('Class', backref=db.backref('units', lazy=True))

class Lecture(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    unit_id = db.Column(db.Integer, db.ForeignKey('unit.id'), nullable=False)
    unit = db.relationship('Unit', backref=db.backref('lectures', lazy=True))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    lecture_id = db.Column(db.Integer, db.ForeignKey('lecture.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('comments', lazy=True))
    lecture = db.relationship('Lecture', backref=db.backref('comments', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    classes = Class.query.all()
    return render_template('index.html', classes=classes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/class/<int:class_id>')
@login_required
def view_class(class_id):
    class_obj = Class.query.get_or_404(class_id)
    return render_template('class.html', class_obj=class_obj)

@app.route('/lecture/<int:lecture_id>')
@login_required
def view_lecture(lecture_id):
    lecture = Lecture.query.get_or_404(lecture_id)
    return render_template('lecture.html', lecture=lecture)

@app.route('/add_comment', methods=['POST'])
@login_required
def add_comment():
    content = request.form['content']
    lecture_id = request.form['lecture_id']
    new_comment = Comment(content=content, user_id=current_user.id, lecture_id=lecture_id)
    db.session.add(new_comment)
    db.session.commit()
    return redirect(url_for('view_lecture', lecture_id=lecture_id))

from flask import current_app

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
