from flask import Flask, render_template, url_for, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import insert
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import sqlite3
 
 
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
                            InputRequired(), Length(min=0, max=20)], render_kw={"placeholder": "Password"})
 
   submit = SubmitField('Register')
 
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
                            InputRequired(), Length(min=0, max=20)], render_kw={"placeholder": "Password"})
 
   submit = SubmitField('Login')
 
 
 
 
@app.route('/login', methods=['GET', 'POST'])
def login():
   conn = sqlite3.connect('part.db')
   conn.row_factory = sqlite3.Row
#  conn = sqlite3.connect('admin.db')
   print("helo")
 
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
                 
                 cur.execute("UPDATE PART_MASTER SET DATE = date('now','localtime') WHERE PART_NAME = ?" ,[partid])
               #   cur.execute("SELECT CONVERT ( CURRENT_TIMESTAMP) AS [DATE] WHERE PART_NAME = ?" ,[partid])

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
                 session["username"] = request.form.get("username")
                 

                 
                 
                
               
               return redirect(url_for('parts'))
 
 
   return render_template('adminlogin.html', form=form) 

@app.route('/parts', methods=['GET', 'POST'])
@login_required
def parts():
  
 conn = sqlite3.connect('part.db')
 conn.row_factory = sqlite3.Row
#  conn = sqlite3.connect('admin.db')
 print("helo")
 
 cur= conn.cursor()

 
   

      #  partid = request.form['partid']


   # sql = ("""SELECT PART_NAME FROM PART_MASTER WHERE PART_NAME = :partid""", {"partid": partid})
#  sql = ("""SELECT MODEL_ID FROM PART_MASTER WHERE PART_NAME = ?  """,{"partid": partid})

  
 
 cur.execute("SELECT * FROM admin ")
 results= cur.fetchall()
 
 
 

 
 
 
     
 conn.commit()   

 return render_template('admindashboard.html', PART_MASTER=results)
 


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
  
 conn = sqlite3.connect('part.db')
 conn.row_factory = sqlite3.Row
#  conn = sqlite3.connect('admin.db')
 print("helo")
 
 cur= conn.cursor()

 
   

      #  partid = request.form['partid']
 partid = (session['partid'])


   # sql = ("""SELECT PART_NAME FROM PART_MASTER WHERE PART_NAME = :partid""", {"partid": partid})
#  sql = ("""SELECT MODEL_ID FROM PART_MASTER WHERE PART_NAME = ?  """,{"partid": partid})

  
 
 cur.execute("SELECT DATE, MODEL_ID, PART_ID_NAME ,CREATE_DATE, SHEET_NAME, PART_NUMBER, EXCEL_FIELD, ID, UPDATE_BY FROM PART_MASTER WHERE PART_NAME = ?  ",[partid])
 results= cur.fetchall()
 
 
 if request.method == "POST":
          

            comment = (session['comment'])
            partid = (session['partid'])
            

            cur.execute(" INSERT INTO admin (ID, PART_NAME,COMMENT)VALUES ((SELECT ID FROM PART_MASTER WHERE PART_NAME=?), (SELECT PART_NAME FROM PART_MASTER WHERE PART_NAME=?), ? )",[(partid),(partid),(comment) ])
            cur.execute("UPDATE admin SET INTIME = time('now','localtime') WHERE PART_NAME = ?" ,[partid])

            rows = ("SELECT * from admin")
            prev_time = None
            for row in rows:
             if prev_time is None:
              prev_time = row.INTIME
             else:
              WAITING_TIME = (row.INTIME - prev_time).total_seconds()
              row.WAITING_TIME = WAITING_TIME
              prev_time = str(row.INTIME)

            db.session.query(admin).update({admin.WAITING_TIME: admin.WAITING_TIME})
            db.session.commit()

            conn.commit()
                      
            return redirect(url_for('login'))

 
 
 
     
 conn.commit()   

 return render_template('dashboard.html', PART_MASTER=results)
 
 

 
 
  
 
 
 
   
 
# @app.route('/total', methods=['GET', 'POST'])
# @login_required
# def total():
#     conn = sqlite3.connect('menu.db')
#     conn.row_factory = sqlite3.Row
    
     
#     cur= conn.cursor()
#     sql = ("""SELECT `food item`,`quantity`  FROM menu WHERE quantity>0""")
  
  
 
#     cur.execute(sql)
#     results= cur.fetchall()  
 
 
  
    
 
#     data=cur.execute("SELECT * FROM menu")
    
#     row2=0
#     for row in data:
#        row1=row[2]*row[3]
#        row2=row2+row1
      
 
#        conn.commit()
      
      
 
    
           
 
 
    
#     return render_template('total.html', row2=row2, menu=results)
    
 
      
 
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
   logout_user()
   return redirect(url_for('login'))
 
 
@ app.route('/register', methods=['GET', 'POST'])
def register():
   form = RegisterForm()
 
   if form.validate_on_submit():
       hashed_password = bcrypt.generate_password_hash(form.password.data)
       new_user = User(username=form.username.data, password=hashed_password)
       db.session.add(new_user)
       db.session.commit()
       return redirect(url_for('login'))
 
   return render_template('register.html', form=form)
 
 
if __name__ == "__main__":
   app.run(debug=True)

