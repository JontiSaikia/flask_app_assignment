from flask import Flask, render_template, url_for, redirect,request,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError,DataRequired,EqualTo, Email
import pandas as pd
from flask_mail import Mail , Message
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from datetime import datetime
import app
#from copy_app import mail
from app import db
#from app import RegistrationForm , LoginForm , ResetRequestForm , ResetPasswordForm
#from flask_bcrypt import Bcrypt

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True 
db = SQLAlchemy(app)
#bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']=587
app.config['MAIL_USE_TLS']=True
app.config['MAIL_USERNAME']='johnsaik769@gmail.com'
app.config['MAIL_PASSWORD']='Temppassword@123'

mail= Mail(app)





@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    email =db.Column(db.String(120),unique=True,nullable=False)
    password = db.Column(db.String(80), nullable=False)
    
    def get_token(self,expires_sec=300):
        serial = Serializer(app.config['SECRET_KEY'],expires_in=expires_sec)
        return serial.dumps({'user_id':self.id}).decode('utf-8')

    @staticmethod # staticmethod will call the token variable just returned in get_token
    def verify_token(token): #or without @staticmethod def verify_token(self,token)
        serial=Serializer(app.config['SECRET_KEY'])
        try:
            user_id=serial.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)
    
    def __repr__(self):
        return f"{self.username}:{self.email}"#:{self.date_created}"


class RegistrationForm(FlaskForm):
    # username = StringField(validators=[
    #                        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    
    # email  = StringField(label='Email',validators=[InputRequired()  ],#render_kw={"placeholder": "email"})

    # password = PasswordField(validators=[
    #                          InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    # submit = SubmitField('Register')
    username = StringField(label='Username', validators=[InputRequired(),Length(min=3,max=20)])
    email  = StringField(label='Email',validators=[InputRequired(),Email()])
    password = PasswordField(label='Password',validators=[InputRequired(), Length(min=6,max=16)])
    confirm_password = PasswordField(label='Confirm Password',validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField(label='Sign Up',validators=[DataRequired()])


    def validate_username(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'That email id already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    email  = StringField(validators=[InputRequired(),Email()],render_kw={"placeholder": "Email"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=6, max=16)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login',validators=[DataRequired()])

       
class ResetRequestForm(FlaskForm):
    email  = StringField(label='Email',validators=[InputRequired(), Email()])
    submit = SubmitField(label='Reset Password',validators=[DataRequired()])
        
class ResetPasswordForm(FlaskForm):
    password = PasswordField(label='Password',validators=[InputRequired(), Length(min=6,max=16)])
    confirm_password = PasswordField(label='Confirm Password',validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField(label='Change Password',validators=[DataRequired()])



@app.route('/')
def home():
    return render_template('home.html')

    #return redirect(url_for('data'))
    #return "<p>This is the user account</p>"
    
@app.route('/pub_dashboard')
def public_dashboard():
    return render_template("pub_dashboard.html")

@app.route('/public_data',methods=["GET","POST"])
def public_data():
    if request.method == "POST":
        f = request.form['uploadfile'] #calling the name= uploadfile object from html
        # data = pd.read_excel(f)
        data = pd.read_excel(f)
        df= data.head(100)
        return render_template('data_2.html',data_2=df.to_csv('export_2.csv',index=False))
        #print("Dataframe shape:", data.shape)
    else:
        return None


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            login_user(user)
            flash('You have logged in Now you are able to upload the excel file and download it in your backend as csv')
            return redirect(url_for('dashboard'))
        else:
            flash('You have logged in Now you are able to upload the excel file and download it in your backend as csv but upto maximum 100 rows ')
            return redirect(url_for('public_dashboard'))
    return render_template('login.html', form=form)


def send_mail(user):
    token=user.get_token()
    msg = Message('Password Reset request', sender = 'yourId@gmail.com', recipients = [user.email])
    msg.body = f"Hello reset message sent from Flask app{url_for('reset_token',token=token,_external=True)}"
    mail.send(msg)
    return "Sent"
    # msg=Message('Password Reset Request',recipients=[user.email],sender='noreply@gmail.com')
    # msg.body=  f" To reset your password follow the link . If you didn't send a password reset request. please ignore the message!{url_for('reset_token',token=token,_external=True)}"


@app.route('/reset_password',methods=['GET','POST'])
def reset_request():
    form=ResetRequestForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first() # here User is the model created by us
        if user:
            send_mail(user)#the user variable will pass to get_token()
            flash('Reset request sent. Check your mail','success')
            return redirect(url_for('login'))
    return render_template('Reset_request.html',title='Reset request',form=form,legend="Reset Password")


@app.route('/reset_password/<token>',methods=['GET','POST']) # since token is a variable we have to pass it inside<>
def reset_token(token):
    user= User.verify_token(token)
    if user is None:
        flash('That is invalid token or expired,please try again!','warning')
        return redirect(url_for('reset_request'))
    
    form=ResetPasswordForm()
    if form.validate_on_submit():
        user.password=form.password.data
        db.session.commit()
        flash('Password changed!Please Login!','success')
        return redirect(url_for('login'))
    return render_template('change_password.html',title="Change Password",legend='Change Password',form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/data',methods=["GET","POST"])
def data():
    if request.method == "POST":
        f = request.form['uploadfile'] #calling the name= uploadfile object from html
        data = pd.read_excel(f)
        flash("Your excel file is converted to export.csv and downloaded automatically on your main directory")
        return render_template('data.html',data=data.to_csv('export.csv',index=False))
    else:
        return None
    


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        #hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data,email=form.email.data, password=form.password.data)
        if not new_user :
            db.session.add(new_user)
            db.session.commit()
            flash('You have registered now you can log in ')
            return redirect(url_for('login'))
        else:
            flash(f"This email id {new_user.email} is already registered , please use a different email id")

    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)

