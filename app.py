import email
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///delitrack.db'
app.config['SECRET_KEY'] = 'VJKHBHVFKHFKVJBH'
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
      return User.query.get(int(user_id))

class User(db.Model, UserMixin):
      id = db.Column(db.Integer, primary_key=True)
      username = db.Column(db.String(20), nullable=True, unique=True)
      lastname = db.Column(db.String(20), nullable=True, unique=True)
      firstname = db.Column(db.String(20), nullable=True)
      email = db.Column(db.String(40), nullable=True, unique=True)
      password = db.Column(db.String(80), nullable=False)

class SignupForm(FlaskForm):
      username = StringField(validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"placeholder": "Username"})

      firstname = StringField(validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"placeholder": "Firstname"})

      lastname = StringField(validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"placeholder": "Lastname"})

      email = StringField(validators=[InputRequired(), Length(
            min=4, max=40)], render_kw={"placeholder": "Email"})

      password = PasswordField(validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"placeholder": "Password"})

      submit = SubmitField("SignUp")

      def validate_username(self, username):
            existing_user_username = User.query.filter_by(
                  username=username.data).first()

            if existing_user_username:
                  raise ValidationError(
                        "That username already exists. Plaese choose a different one.")

      def validate_email(self, email):
            existing_user_email = User.query.filter_by(
                  email=email.data).first()

            if existing_user_email:
                  raise ValidationError(
                        "That email already exists. Plaese choose a different one.")

class ForgotMyPassword(FlaskForm):
      email = StringField(validators=[InputRequired(), Length(
            min=4, max=40)], render_kw={"placeholder": "Email"})

      submit = SubmitField("Forgot Password")

      def validate_email(self, email):
            existing_user_email = User.query.filter_by(
                  email=email.data).first()

            if existing_user_email:
                  raise ValidationError(
                        "That email already exists. Plaese choose a different one.")

class LoginForm(FlaskForm):
      #username = StringField(validators=[InputRequired(), Length(
      #      min=4, max=20)], render_kw={"placeholder": "Username"})

      email = StringField(validators=[InputRequired(), Length(
            min=15, max=40)], render_kw={"placeholder": "Email"})

      password = PasswordField(validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"placeholder": "Password"})

      submit = SubmitField("Login")

@app.route('/')
def index():
    #with app.app_context():
    #    db.create_all()
    return render_template('index.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotMyPassword()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
    return render_template('fgp.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)

#Program starts here   
if __name__ == '__main__':
    app.app_context().push()
    db.create_all()
    app.run(debug=True)