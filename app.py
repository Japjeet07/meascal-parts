from flask import Flask, render_template, url_for, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import insert
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import sqlite3
from datetime import datetime, date,timedelta
import re

 
 
conn = sqlite3.connect('part.db')
conn.row_factory = sqlite3.Row
print("opened successfully")
 
cur= conn.cursor()
 
session_options = {
    'autocommit' : True
}
 
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app, session_options = session_options)

 
 
 
 
 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
 
 
@login_manager.user_loader
def load_user(user_id):
   return User.query.get(int(user_id))
 
 
class User(db.Model, UserMixin):
   id = db.Column(db.Integer, primary_key=True)
   username = db.Column(db.String(20), nullable=False, unique=True)
   password = db.Column(db.String(80), nullable=False)
 
 
 
class RegisterForm(FlaskForm):
   username = StringField(validators=[
                          InputRequired(), Length(min=0, max=20)], render_kw={"placeholder": "Username"})
 
   password = PasswordField(validators=[
                            InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
 
   submit = SubmitField('Register')

   def validate_password(self, password):
       if not re.search(r'\d', password.data):
           raise ValidationError('Password must contain at least one number.')
       if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password.data):
           raise ValidationError('Password must contain at least one special character.')
 
   def validate_username(self, username):
       existing_user_username = User.query.filter_by(
           username=username.data).first()
       if existing_user_username:
           raise ValidationError(
               'That username already exists. Please choose a different one.')
 
 
class LoginForm(FlaskForm):
   username = StringField(validators=[
                          InputRequired(), Length(min=0, max=20)], render_kw={"placeholder": "Username"})
 
   password = PasswordField(validators=[
                            InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
 
   submit = SubmitField('Login')
   
 
 
 
@app.route('/', methods=['GET', 'POST'])
def home():
   form = LoginForm()
   if form.validate_on_submit():
       
       user = User.query.filter_by(username=form.username.data).first()
       print(User.query.filter_by(username=form.username.data).first())
       if user:
           
           if bcrypt.check_password_hash(user.password, form.password.data):
               login_user(user)
               if request.method == "POST":
                 
                return redirect(url_for('login'))
 
 
   return render_template('home.html', form=form) 
 
@app.route('/login', methods=['GET', 'POST'])
@login_required

def login():
   conn = sqlite3.connect('part.db')
   conn.row_factory = sqlite3.Row
 
   cur= conn.cursor()
   form = LoginForm()
   if form.validate_on_submit():
       
       user = User.query.filter_by(username=form.username.data).first()
       print(User.query.filter_by(username=form.username.data).first())
       if user:
           
           if bcrypt.check_password_hash(user.password, form.password.data):
               login_user(user)
               if request.method == "POST":
                 session["username"] = request.form.get("username")
                 session["partid"] = request.form.get("partid")
                 session["comment"] = request.form.get("comment")
                 partid = (session['partid'])
                 
                 cur.execute("UPDATE PART_MASTER SET DATE = datetime('now','localtime') WHERE PART_NAME = ?" ,[partid])

                 conn.commit()

               
               return redirect(url_for('dashboard'))
 
 
   return render_template('login.html', form=form)
 
@app.route('/admin', methods=['GET', 'POST'])
def admin():
   form = LoginForm()
   if form.validate_on_submit():
       
       user = User.query.filter_by(username=form.username.data).first()
       print(User.query.filter_by(username=form.username.data).first())
       if user:
           
           if bcrypt.check_password_hash(user.password, form.password.data):
               login_user(user)
               if request.method == "POST":
                 
                return redirect(url_for('parts'))
 
 
   return render_template('adminlogin.html', form=form) 


@app.route('/entry', methods=['GET', 'POST'])
@login_required
def entry():
    conn = sqlite3.connect('part.db')
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    cur.execute("SELECT * FROM admin ")
    results = cur.fetchall()

    if request.method == "POST":
        partid = session['partid']
        progress = request.form.get("progress")
        cur.execute("UPDATE admin SET PROGRESS = ? WHERE PART_NAME = ?", (progress, partid))
        conn.commit()
        session['progress_updated'] = True
        return redirect(url_for('entry'))

    conn.commit()
    return render_template('adminentry.html', PART_MASTER=results)


@app.route('/parts', methods=['GET', 'POST'])
@login_required
def parts():
    conn = sqlite3.connect('part.db')
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    if 'progress_updated' in session:
        cur.execute("SELECT * FROM admin")
        results = cur.fetchall()
        session.pop('progress_updated', None)
    else:
        
       cur.execute("SELECT * FROM admin WHERE PROGRESS IS NOT NULL")
       results = cur.fetchall()

    conn.commit()
    return render_template('admindashboard.html', PART_MASTER=results)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
  
 conn = sqlite3.connect('part.db')
 conn.row_factory = sqlite3.Row
 
 cur= conn.cursor()

 
 partid = (session['partid'])

 cur.execute("SELECT DATE, MODEL_ID, PART_ID_NAME ,CREATE_DATE, SHEET_NAME, PART_NUMBER, EXCEL_FIELD, ID, UPDATE_BY FROM PART_MASTER WHERE PART_NAME = ?  ",[partid])
 results= cur.fetchall()
 
 cur.execute("SELECT * FROM operation_master WHERE PART_NAME = ?  ",[partid])
 results2= cur.fetchall()
 cur.execute("SELECT COUNT(*) FROM admin")
 count = cur.fetchone()[0]

 if count == 0:
    last_id = 0
 else:
    cur.execute("SELECT ID FROM admin ORDER BY ID DESC LIMIT 1")
    last_id = cur.fetchone()[0]

 new_id = last_id + 1

 if request.method == "POST":
  formatted_operation_time = None  # default value

  if request.form.get("selected_options[]"):

   selected_options = request.form.getlist('selected_options[]')
   selected_options_str = ', '.join([f"'{option}'" for option in selected_options])

   cur.execute(f"SELECT OPERATION_NAME FROM operation_master WHERE OPERATION_ID IN ({selected_options_str}) AND PART_NAME = ?  ",[partid])

  
   rows23 = cur.fetchall()
   operation_names = ', '.join([row[0] for row in rows23])

   cur.execute(f"SELECT OPERATION_TIME FROM operation_master WHERE OPERATION_ID IN ({selected_options_str}) AND PART_NAME = ?  ",[partid])
   rows25 = cur.fetchall()
   if rows25:
       total_operation_time = timedelta()

       for row in rows25:
         operation_time = datetime.strptime(row[0], '%H:%M:%S').time()
         total_operation_time += timedelta(hours=operation_time.hour, minutes=operation_time.minute, seconds=operation_time.second)

       formatted_operation_time = str(total_operation_time).split('.')[0]
       session['formatted_operation_time'] = formatted_operation_time  # store in session

      

   return operation_names


 
 
 if request.form.get("submit"):
  

            comment = (session['comment'])
            partid = (session['partid'])
            formatted_operation_time = session.get('formatted_operation_time')  # retrieve from session



            cur.execute(" INSERT INTO admin (ID, PART_NAME,COMMENT)VALUES (?, (SELECT PART_NAME FROM PART_MASTER WHERE PART_NAME=?), ? )",[(new_id),(partid),(comment) ])
            cur.execute("UPDATE admin SET INTIME = time('now','localtime') WHERE PART_NAME = ?" ,[partid])
          
            cur.execute("UPDATE admin SET INSPECTION_TIME = ? WHERE PART_NAME = ?", [formatted_operation_time, partid])
            conn.commit()


            rows = cur.execute("SELECT * FROM admin").fetchall()
            prev_time = None
            prev2_time = None

            for row in rows:
             

               if prev_time:
                if prev2_time is not None:                   
                 
                   prev3_time = datetime.strptime(prev2_time[4], "%H:%M:%S").time()
                   prev4_time = datetime.strptime(prev_time[3], "%H:%M:%S").time()

                   time_diff = datetime.strptime(row[2], '%H:%M:%S') - datetime.strptime(prev_time[2], '%H:%M:%S') + (datetime.combine(date.today(), prev3_time) - datetime.min)+(datetime.combine(date.today(), prev4_time) - datetime.min)
                   time_diff_seconds = int(time_diff.total_seconds())
                   waiting_time = datetime.utcfromtimestamp(time_diff_seconds).strftime('%H:%M:%S')
                   cur.execute("UPDATE admin SET WAITING_TIME = ? WHERE INTIME = ?", (waiting_time, row[2]))
                   prev2_time = row

                else:
                    prev4_time = datetime.strptime(prev_time[3], "%H:%M:%S").time()

                    time_diff = datetime.strptime(row[2], '%H:%M:%S') -datetime.strptime(prev_time[2], '%H:%M:%S')+(datetime.combine(date.today(), prev4_time) - datetime.min)
                    time_diff_seconds = int(time_diff.total_seconds())

                    waiting_time = datetime.utcfromtimestamp(time_diff_seconds).strftime('%H:%M:%S')

                    cur.execute("UPDATE admin SET WAITING_TIME = ? WHERE INTIME = ?", (waiting_time, row[2]))
                    prev2_time = row
               


               prev_time = row

           


            conn.commit()
                      
            return redirect(url_for('login'))

 
 
 
     
 conn.commit()  
 

 return render_template('dashboard.html', PART_MASTER=results, operation_master=results2,new_id=new_id)
 
 
@ app.route('/register', methods=['GET', 'POST'])
def register():
   form = RegisterForm()
 
   if form.validate_on_submit():
       hashed_password = bcrypt.generate_password_hash(form.password.data)
       new_user = User(username=form.username.data, password=hashed_password)
       db.session.add(new_user)
       db.session.begin(subtransactions=True)

       db.session.commit()
       return redirect(url_for('login'))
 
   return render_template('register.html', form=form)
 
 
if __name__ == "__main__":
   app.run(debug=True)

