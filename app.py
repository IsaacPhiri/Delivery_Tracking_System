from flask import Flask, render_template, url_for, redirect, flash, current_app, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import re
#from flask_mail import Mail, Message
#from itsdangerous import URLSafeTimedSerializer as Serializer

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'VJKHBHVFKHFKVJBH'
db = SQLAlchemy(app)

#app.config['MAIL_SERVER'] = 'smtp.gmail.com'
#app.config['MAIL_PORT'] = 587
#app.config['MAIL_USE_TLS'] = True
#app.config['MAIL_USERNAME'] = 'Isaac Phiri'
#app.config['MAIL_PASSWORD'] = '@2june1964'
#app.config['MAIL_DEFAULT_SENDER'] = 'isaacphiri315@gmail.com'
#mail = Mail(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
      return User.query.get(int(user_id))

class User(db.Model, UserMixin):
      id = db.Column(db.Integer, primary_key=True)
      username = db.Column(db.String(20), nullable=True)
      lastname = db.Column(db.String(20), nullable=True)
      firstname = db.Column(db.String(20), nullable=True)
      email = db.Column(db.String(40), nullable=True, unique=True)
      password = db.Column(db.String(80), nullable=False)

     # def get_reset_password_token(self, expires_in=600):
     #   """Generates a password reset token for the user."""
     #   s = Serializer(current_app.config['SECRET_KEY'], expires_in=expires_in)
     #   return s.dumps({'user_id': self.id}).decode('utf-8')

     # @staticmethod
     # def verify_reset_password_token(token):
     #   """Verifies a password reset token and returns the user if valid."""
     #   s = Serializer(current_app.config['SECRET_KEY'])
     #   try:
     #       data = s.loads(token.encode('utf-8'))
     #   except:
     #       return None
     #   return User.query.get(data['user_id'])

class PasswordValidator:
    def __init__(self, message=None):
        if not message:
            message = 'Password must have at least 6 characters, 1 capital letter, 1 number, and 1 special character'
        self.message = message

    def __call__(self, form, field):
        password = field.data
        if len(password) < 6:
            raise ValidationError(self.message)
        if not re.search("[A-Z]", password):
            raise ValidationError(self.message)
        if not re.search("[0-9]", password):
            raise ValidationError(self.message)
        if not re.search("[@#$%^&+=]", password):
            raise ValidationError(self.message)

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
            min=6, max=20), PasswordValidator()], render_kw={"placeholder": "Password"})

      confirm_password = PasswordField(validators=[InputRequired(), Length(
            min=6, max=20), PasswordValidator()], render_kw={"placeholder": "Confirm Password"})

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
    submit = SubmitField("Reset Password")

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()

        if not user:
            raise ValidationError(
                "There is no account associated with that email.")

        # generate a password reset token
        #token = user.get_reset_password_token()

        # send a password reset email to the user
        #send_password_reset_email(user, token)

        # inform the user that a password reset email has been sent
        flash('An email has been sent with instructions to reset your password.', 'info')


class LoginForm(FlaskForm):
      #username = StringField(validators=[InputRequired(), Length(
      #      min=4, max=20)], render_kw={"placeholder": "Username"})

      email = StringField(validators=[InputRequired(), Length(
            min=15, max=40)], render_kw={"placeholder": "Email"})

      password = PasswordField(validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"placeholder": "Password"})

      submit = SubmitField("Login")

#def send_password_reset_email(user, token):
#    msg = Message('Password Reset Request',
#                  recipients=[user.email])
#    msg.body = f'''To reset your password, visit the following link:
#{url_for('reset_password', token=token, _external=True)}

#If you did not make this request then simply ignore this email and no changes will be made.
#'''
#    mail.send(msg)

@app.route('/')
def index():
    #with app.app_context():
    #    db.create_all()
    return render_template('index.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotMyPassword()
    if form.validate_on_submit():
        #user = User.query.filter_by(email=form.email.data).first()

        #if user:
        #    # generate a password reset token
        #    token = user.get_reset_password_token()

        #    # send a password reset email to the user
        #    send_password_reset_email(user, token)

        #    # inform the user that a password reset email has been sent
        #    flash('An email has been sent with instructions to reset your password.', 'info')
        
        ## always redirect to the homepage after a password reset request
        return redirect(url_for('index'))

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
        password_one = (form.password.data)
        password_two = (form.confirm_password.data)
        if password_one != password_two:
            error_message = "Passwords don't match."
            return jsonify({'error': error_message})
        else:
            hashed_password = bcrypt.generate_password_hash(password_one)
            new_user = User(email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            success_message = "Account created successfully."
            return jsonify({'success': success_message})
            #return redirect(url_for('login'))
    return render_template('signup.html', form=form)

#Program starts here   
if __name__ == '__main__':
    app.app_context().push()
    db.create_all()
    app.run(debug=True)