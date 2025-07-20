"""
Forms with CSRF protection for the password manager
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Length, ValidationError
from security_utils import validate_password_strength, validate_service_name, validate_username

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Length(min=3, max=50, message="Username must be between 3 and 50 characters")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required")
    ])
    submit = SubmitField('Sign In')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Length(min=3, max=50, message="Username must be between 3 and 50 characters")
    ])
    password = PasswordField('Login Password', validators=[
        DataRequired(message="Login password is required")
    ])
    master_password = PasswordField('Master Password', validators=[
        DataRequired(message="Master password is required")
    ])
    submit = SubmitField('Register')
    
    def validate_password(self, field):
        is_valid, error_msg = validate_password_strength(field.data)
        if not is_valid:
            raise ValidationError(error_msg)
    
    def validate_master_password(self, field):
        is_valid, error_msg = validate_password_strength(field.data)
        if not is_valid:
            raise ValidationError(error_msg)

class AddPasswordForm(FlaskForm):
    service_name = StringField('Service Name', validators=[
        DataRequired(message="Service name is required"),
        Length(min=1, max=100, message="Service name must be between 1 and 100 characters")
    ])
    username = StringField('Username', validators=[
        Length(max=100, message="Username must be less than 100 characters")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=1, max=200, message="Password must be between 1 and 200 characters")
    ])
    master_password = PasswordField('Master Password', validators=[
        DataRequired(message="Master password is required")
    ])
    submit = SubmitField('Add Password')
    
    def validate_service_name(self, field):
        is_valid, result = validate_service_name(field.data)
        if not is_valid:
            raise ValidationError(result)
        # Update the field with sanitized data
        field.data = result
    
    def validate_username(self, field):
        if field.data:  # Username is optional
            is_valid, result = validate_username(field.data)
            if not is_valid:
                raise ValidationError(result)
            # Update the field with sanitized data
            field.data = result

class ViewPasswordForm(FlaskForm):
    master_password = PasswordField('Master Password', validators=[
        DataRequired(message="Master password is required")
    ])
    password_id = HiddenField()
    submit = SubmitField('View Password')

class DeletePasswordForm(FlaskForm):
    submit = SubmitField('Delete')