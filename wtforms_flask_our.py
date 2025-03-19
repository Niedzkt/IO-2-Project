from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Email


class RegisterForm(FlaskForm):
    login = StringField('Wpisz login', validators=[DataRequired()])
    email = StringField('Wpisz e-mail', validators=[DataRequired(), Email()])
    password_hash = PasswordField('Wpisz hasło', validators=[
        DataRequired(), 
        Length(min=15, message='Hasło potrzebuje minimum 15 znaków!'),
        EqualTo('password_reply', message='Hasła się nie zgadzają!')])

    password_reply = PasswordField('Powtórz hasło', validators=[DataRequired()])
    submit_button = SubmitField('Zarejestruj się')

class LoginForm(FlaskForm):
    login_or_email = StringField('Login lub e-mail', validators=[DataRequired()], render_kw={"placeholder": "Wpisz login lub e-mail"})
    password = PasswordField('Hasło', validators=[DataRequired()], render_kw={"placeholder": "Wpisz hasło"})
    submit = SubmitField('Zaloguj się')
