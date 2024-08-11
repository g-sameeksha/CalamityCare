from flask import Flask, render_template, redirect, url_for, flash,session,request
from forms import *
from models import db, User, login_manager
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import jsonify



app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login' 


@app.route("/")
def index():
    return render_template("index.html")



@app.route("/home")
@login_required
def home():
    return render_template("home.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = UserForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            full_name=form.full_name.data,
            email=form.email.data,
            phone=form.phone.data,
            
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)  # This handles session management
            session['username'] = user.username
            

            return render_template("home.html")
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.confirm_password.data):
            user.password = generate_password_hash(form.confirm_password.data)
            db.session.commit()
            flash('Your password has been updated!', 'success')
              
            return redirect(url_for('login'))  # Redirect to a logged-in page, e.g., dashboard
        else:
            flash('Invalid email or passwords are not matching', 'danger')
    return render_template('reset_password.html', form=form)



@app.route('/logout')
def logout():
    logout_user()  
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/blog')
@login_required
def weatherblog():
    return render_template("blog.html")

@app.route("/learning")
@login_required
def learning():
    return render_template("quiz.html")


@app.route("/help")
@login_required
def service():
  return render_template("service.html")




@app.route('/about')
@login_required
def About():
    return render_template("about.html")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
