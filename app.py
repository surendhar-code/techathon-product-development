from os import name
from flask import Flask, render_template,request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.orm import relationship

# WSGI application
app=Flask(__name__)


# configuring sqlite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'

# instance of sqlalchemy class
db = SQLAlchemy(app)

# instance of bcrypt for hashing the password
bcrypt = Bcrypt(app)

app.secret_key = 'gfunslmpdbdcx553647y4%8689*&(((&&&'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    confirm_password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False,nullable=False)
    

    def __init__(self, email, password, confirm_password):
        self.email = email
        self.password = password
        self.confirm_password = confirm_password

class Profile(db.Model):
    userid = db.Column(db.Integer,primary_key=True)
    firstname = db.Column(db.String(120), unique=True, nullable=False)
    lastname = db.Column(db.String(120), unique=True, nullable=False)
    mobile = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), primary_key=True)
    degree = db.Column(db.String(120), unique=True, nullable=False)
    department = db.Column(db.String(120), unique=True, nullable=False)
    year = db.Column(db.Integer, unique=True, nullable=False)
    skill1 = db.Column(db.String(120), unique=True, nullable=False)
    skill1_rating = db.Column(db.Integer, primary_key=True)
    skill2 = db.Column(db.String(120), unique=True, nullable=False)
    skill2_rating = db.Column(db.Integer, primary_key=True)
    skill3 = db.Column(db.String(120), unique=True, nullable=False)
    skill3_rating = db.Column(db.Integer, primary_key=True)
    skill4 = db.Column(db.String(120), unique=True, nullable=False)
    skill4_rating = db.Column(db.Integer, primary_key=True)
    skill5 = db.Column(db.String(120), unique=True, nullable=False)
    skill5_rating = db.Column(db.Integer, primary_key=True)
    achievement_name_1 = db.Column(db.String(120), unique=True, nullable=False)
    achievement_desc_1 = db.Column(db.String(120), unique=True, nullable=False)
    achievement_name_2 = db.Column(db.String(120), unique=True, nullable=False)
    achievement_desc_2 = db.Column(db.String(120), unique=True, nullable=False)
    achievement_name_3 = db.Column(db.String(120), unique=True, nullable=False)
    achievement_desc_3 = db.Column(db.String(120), unique=True, nullable=False)
    img = db.Column(db.LargeBinary,nullable=True)
    certificate_1 = db.Column(db.LargeBinary,nullable=True)
    certificate_2 = db.Column(db.LargeBinary,nullable=True)
    
    def __init__(self, userid, firstname, email,):
        self.userid = userid
        self.firstname = firstname
        self.email = email 

        
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/admin')
def admin():
    
    return render_template('admin.html')

@app.route('/signup', methods=['GET','POST'])
def signup():
    message = ''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        users = User.query.all()
        existing_accounts = []
        for user in users:
            account = user.email
            existing_accounts.append(account)
        if email in existing_accounts:
            message="Account already exists...Try with different email address"
        elif password!=confirm_password:
            message="Your Password and Confirm Password not matched. Please type correct password..."
        else:
            # hashing the password and confirm password before storing it into the database.
            hash_password = bcrypt.generate_password_hash(password).decode('utf-8')
            hash_confirm_password = bcrypt.generate_password_hash(confirm_password).decode('utf-8')

            # add the values into the database
            user = User(email=email, password=hash_password, confirm_password = hash_confirm_password)

            db.session.add(user)
            db.session.commit()
            message = "Your account has been created! You are now able to log in', 'success'"
            return redirect(url_for('signin'))
    return render_template('signup.html', message=message)

@app.route('/signin',methods=['GET','POST'])
def signin():
    message=''
    if request.method =='POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        print(user)
        if user and bcrypt.check_password_hash(user.password,password):
            session['user_id'] = user.id
            session['email'] = user.email
            session['is_admin'] = user.is_admin
            session['loggedin'] = True
            if session['is_admin'] == 0:
                return redirect(url_for('home'))
            else:
                return redirect(url_for('admin'))

            
        else:
            message="Log in Unsuccessful. Please check username and password"
        
    
    return render_template("signin.html",message=message)

@app.route('/logout')
def logout():
    session.pop('loggedin', None) 
    session.pop('user_id',None)
    session.pop('is_admin',None)
    session.pop('email',None)
    return redirect(url_for('signin'))

'''@app.route('/create_profile/<int:id>',methods=['POST','GET'])
def create_profile(id):
    if request.method =='POST':
        userid = session['user_id']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        mobile = request.form['mobile']
        email = request.form['email']
        degree = request.form['degree']
        department = request.form['department']
        year = request.form['year']
        skill1 = request.form['skill1']
        skill1_rating = request.form['skill1_rating']
        skill2 = request.form['skill2']
        skill2_rating = request.form['skill2_rating']
        skill3 = request.form['skill3']
        skill3_rating = request.form['skill3_rating']
        skill4 = request.form['skill4']
        skill4_rating = request.form['skill4_rating']
        skill5 = request.form['skill5']
        skill5_rating = request.form['skill5_rating']
        achievement_name1 = request.form['achievement_name1']
        achievement_desc_1 = request.form['achievement_desc_1']
        achievement_name2 = request.form['achievement_name2']
        achievement_desc_2 = request.form['achievement_desc_2']
        achievement_name3 = request.form['achievement_name3']
        achievement_desc_3 = request.form['achievement_desc_3']
        img = request.form['img']
        certificate_1 = request.form['certificate_1']
        certificate_2 = request.form['certificate_2']

        profile = Profile(userid=userid, firstname=firstname,lastname=lastname,mobile=mobile,
        email=email,degree=degree,department=department,year=year,skill1=skill1,skill1_rating=skill1_rating, skill2=skill2,skill2_rating=skill2_rating,skill3=skill3,skill3_rating=skill3_rating,skill4=skill4,skill4_rating=skill4_rating,skill5=skill5,skill5_rating=skill5_rating,achievement_name1=achievement_name1,achievement_desc_1=achievement_desc_1,achievement_name2=achievement_name2,achievement_desc_2=achievement_desc_2,achievement_name3=achievement_name3,img=img,certificate_1 = certificate_1)'''












if __name__=='__main__':
    app.run(debug=True,use_reloader=False)

