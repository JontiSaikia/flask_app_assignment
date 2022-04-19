from flask import Flask, render_template, url_for, redirect,request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError,DataRequired,EqualTo, Email
import pandas as pd

#from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True 
db = SQLAlchemy(app)
#bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    email =db.Column(db.String(120),unique=True,nullable=False)
    password = db.Column(db.String(80), nullable=False)


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
    submit = SubmitField(label='Sign Up')


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

    submit = SubmitField('Login')


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
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('public_dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/data',methods=["GET","POST"])
def data():
    if request.method == "POST":
        f = request.form['uploadfile'] #calling the name= uploadfile object from html
        data = pd.read_excel(f)
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
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)

