from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField

##WTForm
class LoginUserForm(FlaskForm):
    email = EmailField("Email", validators=[Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")
