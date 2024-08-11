# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,TextAreaField,FileField
from wtforms.validators import DataRequired, Email, Length, Regexp, ValidationError
from models import User

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=50)])
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    phone = StringField('Phone', validators=[
        DataRequired(), 
        Length(min=10, max=15), 
        Regexp(r'^[0-9]+$', message="Phone number must contain only digits.")
    ])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already registered. Please use a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')





class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Reset Password')

    def validate_confirm_password(self, confirm_password):
        if confirm_password.data != self.password.data:
            raise ValidationError('Passwords must match.')


