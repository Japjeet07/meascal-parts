from flask import Flask, render_template, url_for, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import insert
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import sqlite3
import re
import os
import json
from flask_login import current_user
from flask import Flask, render_template, request, session, redirect, url_for, flash, make_response
import time
from flask import request, jsonify
from datetime import datetime, date,timedelta
import datetime as dt
from collections import defaultdict









 
 
conn = sqlite3.connect('part.db')
conn.row_factory = sqlite3.Row
print("opened successfully")
 
cur= conn.cursor()
 
session_options = {
    'autoflush': True
}
app = Flask(__name__)
bcrypt = Bcrypt(app)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database.db')

app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
db.session = db._make_scoped_session(options=session_options)

# db = SQLAlchemy(app)


 

 
 
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
   is_admin = db.Column(db.Boolean, default=False)
   role = db.Column(db.String(10), nullable=False, default='user')

 
 
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
    conn = sqlite3.connect('part.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
   
    form = LoginForm()
    cur.execute("SELECT * FROM TOOLROOM_MASTER")
    results = cur.fetchall()
    print(results)
    conn.commit()
   
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        print(User.query.filter_by(username=form.username.data).first())
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            if request.method == "POST":
                if request.form.get("submit"):
                    toolroom = request.form.get("toolroom")
                    session['loginroom'] = True
                    session['toolroomlog'] = toolroom
                    return redirect(url_for('login', toolroom=toolroom))
            else:
                return redirect(url_for('login'))

    return render_template('home.html', form=form, results=results)

        

@app.route('/login/<toolroom>', methods=['GET', 'POST'])
@login_required

def login(toolroom):
  if 'toolroomlog' in session and session['toolroomlog'] == toolroom:


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
                 session['loginroom'] = True
                 session['toolroomsess'] = toolroom
                 session["priority"] = request.form.get("priority")

                 
                 cur.execute("UPDATE PART_MASTER SET DATE = datetime('now','localtime') WHERE PART_NAME = ?" ,[partid])

                 conn.commit()

               return redirect(url_for('dashboard', toolroom=toolroom))
  else:
   
   return redirect(url_for('/'))
   
  return render_template('login.html', form=form, toolroom=toolroom)
 

 
 
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            user.is_admin = True
            user.role = 'admin'
            db.session.commit()
            login_user(user)
            session['adminsess'] = True
            return redirect(url_for('admindiscovery'))

    return render_template('adminlogin.html', form=form)


@app.route('/admindiscovery', methods=['GET', 'POST'])
@login_required
def admindiscovery():
    if current_user.is_authenticated and current_user.is_admin:
        conn = sqlite3.connect('part.db')
        conn.row_factory = sqlite3.Row

        cur = conn.cursor()  
        cur.execute("SELECT * FROM TOOLROOM_MASTER")
        results = cur.fetchall()
        
        # if request.method == "POST":
        #     if request.form.get("submit"):
                # toolroom = request.form.get("toolroomadmin")
                # print(toolroom)
                # return redirect(url_for('toolroomadmin', toolroom=toolroom))
        
        conn.commit()
        return render_template('discovery.html', results=results)
    
    flash('You do not have access to the admin page.')
    return redirect(url_for('admin'))


@app.route('/toolroomadmin/<toolroom>', methods=['GET', 'POST'])
def toolroomadmin(toolroom):
   if 'toolroomadmin' in session and session['toolrooomadmin'] == toolroom:

    conn = sqlite3.connect('part.db')
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    cur.execute("SELECT * FROM admin WHERE TOOLROOM=?", [toolroom])

    results = cur.fetchall()
    partid = session.get('partid') 
    
    
    
    

    if request.method == 'POST':
     if request.form.get('newoperation'):
      partname = request.form.get('partname')
      partnames = request.form.get('partnames')


    # Update the status of the selected part to "Approved"
      cur.execute("UPDATE admin SET STATUS = 'Approved' WHERE PART_NAME = ?", [partnames])
   
      operation_name = request.form.get('operation')
      print(operation_name)
      new_operation_name = request.form.get('newoperation')
      print(new_operation_name)
      if new_operation_name == "null" :
        print("hello")
        cur.execute("UPDATE admin SET OPERATION_NAMES = ? WHERE PART_NAME = ?", ["", partname])
        cur.execute("DELETE FROM admin WHERE PART_NAME = ?", [partname])

        rows =  cur.execute("SELECT * FROM admin WHERE TOOLROOM=?", [toolroom]).fetchall()
        prev_waiting_time = None
        toolroom_dict2 = defaultdict(list)


        for row in rows:
              current_toolroom = row[7]
              current_waiting_time = None
    
              if current_toolroom not in toolroom_dict2:
        # This is the first part we're seeing from this toolroom
               toolroom_dict2[current_toolroom].append(row)
              else:
               prev_parts_from_toolroom = toolroom_dict2[current_toolroom]
               prev_matching_parts = [prev_row for prev_row in prev_parts_from_toolroom if prev_row[0] != row[0] and prev_row[7] == current_toolroom]
        
               if prev_matching_parts:
            # There are previous parts from the same toolroom, calculate waiting time
                 prev_part = prev_matching_parts[-1]
                 prev_waiting_time = prev_part[5]
                 prev_inspection_time = prev_part[6]
                 prev_intime = prev_part[2]
                 prev3_time = None
                 if prev_part[4] is not None:
                        hello=cur.execute("SELECT WAITING_TIME FROM admin WHERE PART_NAME=? ",(prev_part[0],)).fetchone()[0]
                        prev3_time = datetime.strptime(hello, "%H:%M:%S").time() if hello is not None else None

                 prev4_time = datetime.strptime(prev_part[3], "%H:%M:%S").time()
                 if prev3_time is not None:
                     time_diff =  (datetime.combine(date.today(), prev3_time) - datetime.min)+(datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') - datetime.strptime(prev_intime, '%H:%M:%S') ) 
                 else :
                     time_diff = (datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') -datetime.strptime(prev_intime, '%H:%M:%S'))
                        
                 time_diff_seconds = int(time_diff.total_seconds())
                 current_waiting_time = datetime.utcfromtimestamp(time_diff_seconds).strftime('%H:%M:%S')
                
               else:
            # No previous parts from this toolroom, waiting time is None
                current_waiting_time = None

        
        # Append the current part to the list of parts from this toolroom
              toolroom_dict2[current_toolroom].append(row)

              cur.execute("UPDATE admin SET WAITING_TIME = ? WHERE PART_NAME = ?", (current_waiting_time, row[0]))
    
   
       
      else:
        
        print(new_operation_name)
        print("bad")
        cur.execute("UPDATE admin SET OPERATION_NAMES = ? WHERE PART_NAME = ?", [new_operation_name, partname])

      # get the part master record
      
        
        cur.execute(f"SELECT operation FROM PART_MASTER WHERE PART_NAME = ?", [partname])
        operation_json = cur.fetchone()[0]
        operation_data = json.loads(operation_json)

        operation_record = None
        for record in operation_data:
         if record['process'] == operation_name:
            operation_record = record
            break

        operation_time_str = operation_record['time']
        operation_time = int(operation_time_str)

        cur.execute(f"SELECT INSPECTION_TIME FROM admin WHERE PART_NAME = ?", [partname])

        inspection_time_str = cur.fetchone()[0]

        # convert inspection_time_str to datetime object
        inspection_time = dt.datetime.strptime(inspection_time_str, '%H:%M:%S')


        
        # subtract operation time from inspection time
        new_inspection_time = inspection_time - dt.timedelta(minutes=operation_time)

        # convert new_inspection_time back to string
        new_inspection_time_str = new_inspection_time.strftime('%H:%M:%S')
        cur.execute(f"UPDATE admin SET INSPECTION_TIME = ? WHERE PART_NAME = ?", [new_inspection_time_str, partname])
        
            
        toolroom_dict = defaultdict(list)

            

        rows =    cur.execute("SELECT * FROM admin WHERE TOOLROOM=?", [toolroom]).fetchall()
        prev_waiting_time = None

        for row in rows:
                current_toolroom = row[7]
                current_waiting_time = None
        
                if current_toolroom not in toolroom_dict:
            # This is the first part we're seeing from this toolroom
                 toolroom_dict[current_toolroom].append(row)
                else:
                 prev_parts_from_toolroom = toolroom_dict[current_toolroom]
                 prev_matching_parts = [prev_row for prev_row in prev_parts_from_toolroom if prev_row[0] != row[0] and prev_row[7] == current_toolroom]
            
                 if prev_matching_parts:
                # There are previous parts from the same toolroom, calculate waiting time
                    prev_part = prev_matching_parts[-1]
                    prev_waiting_time = prev_part[5]
                    prev_inspection_time = prev_part[6]
                    prev_intime = prev_part[2]
                    prev3_time = None
                    if prev_part[4] is not None:
                        hello=cur.execute("SELECT WAITING_TIME FROM admin WHERE PART_NAME=? ",(prev_part[0],)).fetchone()[0]
                        prev3_time = datetime.strptime(hello, "%H:%M:%S").time()

                    prev4_time = datetime.strptime(prev_part[3], "%H:%M:%S").time()
                    if prev3_time is not None:
                     time_diff = (datetime.combine(date.today(), prev3_time) - datetime.min)+(datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') - datetime.strptime(prev_intime, '%H:%M:%S'))
                    else :
                     time_diff = (datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') -datetime.strptime(prev_intime, '%H:%M:%S'))
                        
                    time_diff_seconds = int(time_diff.total_seconds())
                    current_waiting_time = datetime.utcfromtimestamp(time_diff_seconds).strftime('%H:%M:%S')
                
                 else:
                # No previous parts from this toolroom, waiting time is None
                  current_waiting_time = None
            
            # Append the current part to the list of parts from this toolroom
                toolroom_dict[current_toolroom].append(row)
                
                cur.execute("UPDATE admin SET WAITING_TIME = ? WHERE PART_NAME = ?", (current_waiting_time, row[0]))
    

     if request.form.get('addedoperation'):
             addedoperation=request.form.get('addedoperation')
             print(addedoperation)
             partname2 = request.form.get('partname2')
             cur.execute("UPDATE admin SET OPERATION_NAMES = ? WHERE PART_NAME = ?", [ addedoperation, partname2])
    
             operation_name2 = request.form.get('addoperationName')
             print(operation_name2)
             new_operation_name = request.form.get('addedoperation')
             print(new_operation_name)
                
                # get the part master record
             cur.execute(f"SELECT operation FROM PART_MASTER WHERE PART_NAME = ?", [partname2])
             operation_json = cur.fetchone()[0]
             operation_data = json.loads(operation_json)

             operation_record = None
             for record in operation_data:
                if record['process'] == operation_name2:
                    operation_record = record
                    break

             operation_time_str = operation_record['time']
             operation_time = int(operation_time_str)

             cur.execute(f"SELECT INSPECTION_TIME FROM admin WHERE PART_NAME = ?", [partname2])

             inspection_time_str = cur.fetchone()[0]

                # convert inspection_time_str to datetime object
             inspection_time = dt.datetime.strptime(inspection_time_str, '%H:%M:%S')


                
                # add operation time from inspection time
             new_inspection_time = inspection_time + dt.timedelta(minutes=operation_time)
             
                # convert new_inspection_time back to string
             new_inspection_time_str = new_inspection_time.strftime('%H:%M:%S')
             print(new_inspection_time_str)
             cur.execute(f"UPDATE admin SET INSPECTION_TIME = ? WHERE PART_NAME = ?", [new_inspection_time_str, partname2])
                
                    
             toolroom_dict = defaultdict(list)

                    

             rows =     cur.execute("SELECT * FROM admin WHERE TOOLROOM=?", [toolroom]).fetchall()
             prev_waiting_time = None

             for row in rows:
              current_toolroom = row[7]
              current_waiting_time = None
    
              if current_toolroom not in toolroom_dict:
        # This is the first part we're seeing from this toolroom
               toolroom_dict[current_toolroom].append(row)
              else:
               prev_parts_from_toolroom = toolroom_dict[current_toolroom]
               prev_matching_parts = [prev_row for prev_row in prev_parts_from_toolroom if prev_row[0] != row[0] and prev_row[7] == current_toolroom]
        
               if prev_matching_parts:
            # There are previous parts from the same toolroom, calculate waiting time
                  prev_part = prev_matching_parts[-1]
                  prev_waiting_time = prev_part[5]
                  prev_inspection_time = prev_part[6]
                  prev_intime = prev_part[2]
                  prev3_time = None
                  if prev_part[4] is not None:
                      hello=cur.execute("SELECT WAITING_TIME FROM admin WHERE PART_NAME=? ",(prev_part[0],)).fetchone()[0]
                      prev3_time = datetime.strptime(hello, "%H:%M:%S").time()

                  prev4_time = datetime.strptime(prev_part[3], "%H:%M:%S").time()
                  if prev3_time is not None:
                   time_diff = (datetime.combine(date.today(), prev3_time) - datetime.min)+(datetime.combine(date.today(), prev4_time) - datetime.min) -(datetime.strptime(row[2], '%H:%M:%S') - datetime.strptime(prev_intime, '%H:%M:%S') )
                  else :
                   time_diff = (datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') -datetime.strptime(prev_intime, '%H:%M:%S'))
                    
                  time_diff_seconds = int(time_diff.total_seconds())
                  current_waiting_time = datetime.utcfromtimestamp(time_diff_seconds).strftime('%H:%M:%S')
            
               else:
            # No previous parts from this toolroom, waiting time is None
                current_waiting_time = None
        
        # Append the current part to the list of parts from this toolroom
               toolroom_dict[current_toolroom].append(row)

              cur.execute("UPDATE admin SET WAITING_TIME = ? WHERE PART_NAME = ?", (current_waiting_time, row[0]))
    
    if request.form.get("goback"):
       del session['toolroomadmin']         
       return redirect(url_for('toollogin'))

    conn.commit()
    return render_template('toolroomadmin.html', PART_MASTER=results, partid=partid,toolroom=toolroom)




@app.route('/entry', methods=['GET', 'POST'])
@login_required
def entry():
  
    conn = sqlite3.connect('part.db')
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    cur.execute("SELECT * FROM admin")

    results = cur.fetchall()
    partid = session.get('partid') 
    
    
    
    

    if request.method == 'POST':
     partnames = request.form.get('partnames')


    # Update the status of the selected part to "Approved"
     cur.execute("UPDATE admin SET STATUS = 'Approved' WHERE PART_NAME = ?", [partnames])
   
     if request.form.get('newoperation'):
      partname = request.form.get('partname')
      
      operation_name = request.form.get('operation')
      print(operation_name)
      new_operation_name = request.form.get('newoperation')
      print(new_operation_name)
      if new_operation_name == "null" :
        print("hello")
        cur.execute("UPDATE admin SET OPERATION_NAMES = ? WHERE PART_NAME = ?", ["", partname])
        # cur.execute("DELETE FROM admin WHERE PART_NAME = ?", [partname])

        rows = cur.execute("SELECT * FROM admin").fetchall()
        prev_waiting_time = None
        toolroom_dict2 = defaultdict(list)


        for row in rows:
              current_toolroom = row[7]
              current_waiting_time = None
    
              if current_toolroom not in toolroom_dict2:
        # This is the first part we're seeing from this toolroom
               toolroom_dict2[current_toolroom].append(row)
              else:
               prev_parts_from_toolroom = toolroom_dict2[current_toolroom]
               prev_matching_parts = [prev_row for prev_row in prev_parts_from_toolroom if prev_row[0] != row[0] and prev_row[7] == current_toolroom]
        
               if prev_matching_parts:
            # There are previous parts from the same toolroom, calculate waiting time
                 prev_part = prev_matching_parts[-1]
                 prev_waiting_time = prev_part[5]
                 prev_inspection_time = prev_part[6]
                 prev_intime = prev_part[2]
                 prev3_time = None
                 if prev_part[4] is not None:
                        hello=cur.execute("SELECT WAITING_TIME FROM admin WHERE PART_NAME=? ",(prev_part[0],)).fetchone()[0]
                        prev3_time = datetime.strptime(hello, "%H:%M:%S").time() if hello is not None else None

                 prev4_time = datetime.strptime(prev_part[3], "%H:%M:%S").time()
                 if prev3_time is not None:
                     time_diff =  (datetime.combine(date.today(), prev3_time) - datetime.min)+(datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') - datetime.strptime(prev_intime, '%H:%M:%S') ) 
                 else :
                     time_diff = (datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') -datetime.strptime(prev_intime, '%H:%M:%S'))
                        
                 time_diff_seconds = int(time_diff.total_seconds())
                 current_waiting_time = datetime.utcfromtimestamp(time_diff_seconds).strftime('%H:%M:%S')
                
               else:
            # No previous parts from this toolroom, waiting time is None
                current_waiting_time = None

        
        # Append the current part to the list of parts from this toolroom
              toolroom_dict2[current_toolroom].append(row)

              cur.execute("UPDATE admin SET WAITING_TIME = ? WHERE PART_NAME = ?", (current_waiting_time, row[0]))
    
   
       
      else:
        
        print(new_operation_name)
        print("bad")
        cur.execute("UPDATE admin SET OPERATION_NAMES = ? WHERE PART_NAME = ?", [new_operation_name, partname])

      # get the part master record
      
        
        cur.execute(f"SELECT operation FROM PART_MASTER WHERE PART_NAME = ?", [partname])
        operation_json = cur.fetchone()[0]
        operation_data = json.loads(operation_json)

        operation_record = None
        for record in operation_data:
         if record['process'] == operation_name:
            operation_record = record
            break

        operation_time_str = operation_record['time']
        operation_time = int(operation_time_str)

        cur.execute(f"SELECT INSPECTION_TIME FROM admin WHERE PART_NAME = ?", [partname])

        inspection_time_str = cur.fetchone()[0]

        # convert inspection_time_str to datetime object
        inspection_time = dt.datetime.strptime(inspection_time_str, '%H:%M:%S')


        
        # subtract operation time from inspection time
        new_inspection_time = inspection_time - dt.timedelta(minutes=operation_time)

        # convert new_inspection_time back to string
        new_inspection_time_str = new_inspection_time.strftime('%H:%M:%S')
        cur.execute(f"UPDATE admin SET INSPECTION_TIME = ? WHERE PART_NAME = ?", [new_inspection_time_str, partname])
        
            
        toolroom_dict = defaultdict(list)

            

        rows = cur.execute("SELECT * FROM admin").fetchall()
        prev_waiting_time = None

        for row in rows:
                current_toolroom = row[7]
                current_waiting_time = None
        
                if current_toolroom not in toolroom_dict:
            # This is the first part we're seeing from this toolroom
                 toolroom_dict[current_toolroom].append(row)
                else:
                 prev_parts_from_toolroom = toolroom_dict[current_toolroom]
                 prev_matching_parts = [prev_row for prev_row in prev_parts_from_toolroom if prev_row[0] != row[0] and prev_row[7] == current_toolroom]
            
                 if prev_matching_parts:
                # There are previous parts from the same toolroom, calculate waiting time
                    prev_part = prev_matching_parts[-1]
                    prev_waiting_time = prev_part[5]
                    prev_inspection_time = prev_part[6]
                    prev_intime = prev_part[2]
                    prev3_time = None
                    if prev_part[4] is not None:
                        hello=cur.execute("SELECT WAITING_TIME FROM admin WHERE PART_NAME=? ",(prev_part[0],)).fetchone()[0]
                        prev3_time = datetime.strptime(hello, "%H:%M:%S").time()

                    prev4_time = datetime.strptime(prev_part[3], "%H:%M:%S").time()
                    if prev3_time is not None:
                     time_diff = (datetime.combine(date.today(), prev3_time) - datetime.min)+(datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') - datetime.strptime(prev_intime, '%H:%M:%S'))
                    else :
                     time_diff = (datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') -datetime.strptime(prev_intime, '%H:%M:%S'))
                        
                    time_diff_seconds = int(time_diff.total_seconds())
                    current_waiting_time = datetime.utcfromtimestamp(time_diff_seconds).strftime('%H:%M:%S')
                
                 else:
                # No previous parts from this toolroom, waiting time is None
                  current_waiting_time = None
            
            # Append the current part to the list of parts from this toolroom
                toolroom_dict[current_toolroom].append(row)
                
                cur.execute("UPDATE admin SET WAITING_TIME = ? WHERE PART_NAME = ?", (current_waiting_time, row[0]))
    

     if request.form.get('addedoperation'):
             addedoperation=request.form.get('addedoperation')
             print(addedoperation)
             partname2 = request.form.get('partname2')
             cur.execute("UPDATE admin SET OPERATION_NAMES = ? WHERE PART_NAME = ?", [ addedoperation, partname2])
    
             operation_name2 = request.form.get('addoperationName')
             print(operation_name2)
             new_operation_name = request.form.get('addedoperation')
             print(new_operation_name)
                
                # get the part master record
             cur.execute(f"SELECT operation FROM PART_MASTER WHERE PART_NAME = ?", [partname2])
             operation_json = cur.fetchone()[0]
             operation_data = json.loads(operation_json)

             operation_record = None
             for record in operation_data:
                if record['process'] == operation_name2:
                    operation_record = record
                    break

             operation_time_str = operation_record['time']
             operation_time = int(operation_time_str)

             cur.execute(f"SELECT INSPECTION_TIME FROM admin WHERE PART_NAME = ?", [partname2])

             inspection_time_str = cur.fetchone()[0]

                # convert inspection_time_str to datetime object
             inspection_time = dt.datetime.strptime(inspection_time_str, '%H:%M:%S')


                
                # add operation time from inspection time
             new_inspection_time = inspection_time + dt.timedelta(minutes=operation_time)
             
                # convert new_inspection_time back to string
             new_inspection_time_str = new_inspection_time.strftime('%H:%M:%S')
             print(new_inspection_time_str)
             cur.execute(f"UPDATE admin SET INSPECTION_TIME = ? WHERE PART_NAME = ?", [new_inspection_time_str, partname2])
                
                    
             toolroom_dict = defaultdict(list)

                    

             rows = cur.execute("SELECT * FROM admin").fetchall()
             prev_waiting_time = None

             for row in rows:
              current_toolroom = row[7]
              current_waiting_time = None
    
              if current_toolroom not in toolroom_dict:
        # This is the first part we're seeing from this toolroom
               toolroom_dict[current_toolroom].append(row)
              else:
               prev_parts_from_toolroom = toolroom_dict[current_toolroom]
               prev_matching_parts = [prev_row for prev_row in prev_parts_from_toolroom if prev_row[0] != row[0] and prev_row[7] == current_toolroom]
        
               if prev_matching_parts:
            # There are previous parts from the same toolroom, calculate waiting time
                  prev_part = prev_matching_parts[-1]
                  prev_waiting_time = prev_part[5]
                  prev_inspection_time = prev_part[6]
                  prev_intime = prev_part[2]
                  prev3_time = None
                  if prev_part[4] is not None:
                      hello=cur.execute("SELECT WAITING_TIME FROM admin WHERE PART_NAME=? ",(prev_part[0],)).fetchone()[0]
                      prev3_time = datetime.strptime(hello, "%H:%M:%S").time()

                  prev4_time = datetime.strptime(prev_part[3], "%H:%M:%S").time()
                  if prev3_time is not None:
                   time_diff = (datetime.combine(date.today(), prev3_time) - datetime.min)+(datetime.combine(date.today(), prev4_time) - datetime.min) -(datetime.strptime(row[2], '%H:%M:%S') - datetime.strptime(prev_intime, '%H:%M:%S') )
                  else :
                   time_diff = (datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') -datetime.strptime(prev_intime, '%H:%M:%S'))
                    
                  time_diff_seconds = int(time_diff.total_seconds())
                  current_waiting_time = datetime.utcfromtimestamp(time_diff_seconds).strftime('%H:%M:%S')
            
               else:
            # No previous parts from this toolroom, waiting time is None
                current_waiting_time = None
        
        # Append the current part to the list of parts from this toolroom
               toolroom_dict[current_toolroom].append(row)

              cur.execute("UPDATE admin SET WAITING_TIME = ? WHERE PART_NAME = ?", (current_waiting_time, row[0]))
    
   

    conn.commit()
    return render_template('adminentry.html', PART_MASTER=results, partid=partid)



@app.route('/parts', methods=['GET', 'POST'])
@login_required
def parts():
    conn = sqlite3.connect('part.db')
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
   
    cur.execute("SELECT * FROM admin WHERE STATUS = 'Approved'")

    results = cur.fetchall()

    conn.commit()
    return render_template('admindashboard.html', PART_MASTER=results)


@app.route('/operation', methods=['GET', 'POST'])
@login_required
def operation():
  
    conn = sqlite3.connect('part.db')
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    cur.execute("SELECT * FROM admin WHERE STATUS = 'Approved'")

    results = cur.fetchall()
    partid = session.get('partid') 
    
    
    
    

    if request.method == 'POST':
     if request.form.get('newoperation'):
      partname = request.form.get('partname')
      operation_name = request.form.get('operation')
      print(operation_name)
      new_operation_name = request.form.get('newoperation')
      print(new_operation_name)
      if new_operation_name == "null" :
        print("hello")
        cur.execute("UPDATE admin SET OPERATION_NAMES = ? WHERE PART_NAME = ?", ["", partname])
        cur.execute("DELETE FROM admin WHERE PART_NAME = ?", [partname])

        rows = cur.execute("SELECT * FROM admin WHERE STATUS = 'Approved'").fetchall()
        prev_waiting_time = None
        toolroom_dict2 = defaultdict(list)

        for row in rows:
              current_toolroom = row[7]
              current_waiting_time = None
    
              if current_toolroom not in toolroom_dict2:
        # This is the first part we're seeing from this toolroom
               toolroom_dict2[current_toolroom].append(row)
              else:
               prev_parts_from_toolroom = toolroom_dict2[current_toolroom]
               prev_matching_parts = [prev_row for prev_row in prev_parts_from_toolroom if prev_row[0] != row[0] and prev_row[7] == current_toolroom]
        
               if prev_matching_parts:
            # There are previous parts from the same toolroom, calculate waiting time
                 prev_part = prev_matching_parts[-1]
                 prev_waiting_time = prev_part[5]
                 prev_inspection_time = prev_part[6]
                 prev_intime = prev_part[2]
                 prev3_time = None
                 if prev_part[4] is not None:
                        hello=cur.execute("SELECT WAITING_TIME FROM admin WHERE PART_NAME=? ",(prev_part[0],)).fetchone()[0]
                        prev3_time = datetime.strptime(hello, "%H:%M:%S").time() if hello is not None else None

                 prev4_time = datetime.strptime(prev_part[3], "%H:%M:%S").time()
                 if prev3_time is not None:
                     time_diff =  (datetime.combine(date.today(), prev3_time) - datetime.min)+(datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') - datetime.strptime(prev_intime, '%H:%M:%S') ) 
                 else :
                     time_diff = (datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') -datetime.strptime(prev_intime, '%H:%M:%S'))
                        
                 time_diff_seconds = int(time_diff.total_seconds())
                 current_waiting_time = datetime.utcfromtimestamp(time_diff_seconds).strftime('%H:%M:%S')
                
               else:
            # No previous parts from this toolroom, waiting time is None
                current_waiting_time = None

        
        # Append the current part to the list of parts from this toolroom
              toolroom_dict2[current_toolroom].append(row)

              cur.execute("UPDATE admin SET WAITING_TIME = ? WHERE PART_NAME = ?", (current_waiting_time, row[0]))
    
   
       
      else:
        
        print(new_operation_name)
        print("bad")
        cur.execute("UPDATE admin SET OPERATION_NAMES = ? WHERE PART_NAME = ?", [new_operation_name, partname])

      # get the part master record
      
        
        cur.execute(f"SELECT operation FROM PART_MASTER WHERE PART_NAME = ?", [partname])
        operation_json = cur.fetchone()[0]
        operation_data = json.loads(operation_json)

        operation_record = None
        for record in operation_data:
         if record['process'] == operation_name:
            operation_record = record
            break

        operation_time_str = operation_record['time']
        operation_time = int(operation_time_str)

        cur.execute(f"SELECT INSPECTION_TIME FROM admin WHERE PART_NAME = ?", [partname])

        inspection_time_str = cur.fetchone()[0]

        # convert inspection_time_str to datetime object
        inspection_time = dt.datetime.strptime(inspection_time_str, '%H:%M:%S')


        
        # subtract operation time from inspection time
        new_inspection_time = inspection_time - dt.timedelta(minutes=operation_time)

        # convert new_inspection_time back to string
        new_inspection_time_str = new_inspection_time.strftime('%H:%M:%S')
        cur.execute(f"UPDATE admin SET INSPECTION_TIME = ? WHERE PART_NAME = ?", [new_inspection_time_str, partname])
        
            
        toolroom_dict = defaultdict(list)

            

        rows = cur.execute("SELECT * FROM admin WHERE STATUS = 'Approved'").fetchall()
        prev_waiting_time = None

        for row in rows:
                current_toolroom = row[7]
                current_waiting_time = None
        
                if current_toolroom not in toolroom_dict:
            # This is the first part we're seeing from this toolroom
                 toolroom_dict[current_toolroom].append(row)
                else:
                 prev_parts_from_toolroom = toolroom_dict[current_toolroom]
                 prev_matching_parts = [prev_row for prev_row in prev_parts_from_toolroom if prev_row[0] != row[0] and prev_row[7] == current_toolroom]
            
                 if prev_matching_parts:
                # There are previous parts from the same toolroom, calculate waiting time
                    prev_part = prev_matching_parts[-1]
                    prev_waiting_time = prev_part[5]
                    prev_inspection_time = prev_part[6]
                    prev_intime = prev_part[2]
                    prev3_time = None
                    if prev_part[4] is not None:
                        hello=cur.execute("SELECT WAITING_TIME FROM admin WHERE PART_NAME=? ",(prev_part[0],)).fetchone()[0]
                        prev3_time = datetime.strptime(hello, "%H:%M:%S").time()

                    prev4_time = datetime.strptime(prev_part[3], "%H:%M:%S").time()
                    if prev3_time is not None:
                     time_diff = (datetime.combine(date.today(), prev3_time) - datetime.min)+(datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') - datetime.strptime(prev_intime, '%H:%M:%S'))
                    else :
                     time_diff = (datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') -datetime.strptime(prev_intime, '%H:%M:%S'))
                        
                    time_diff_seconds = int(time_diff.total_seconds())
                    current_waiting_time = datetime.utcfromtimestamp(time_diff_seconds).strftime('%H:%M:%S')
                
                 else:
                # No previous parts from this toolroom, waiting time is None
                  current_waiting_time = None
            
            # Append the current part to the list of parts from this toolroom
                toolroom_dict[current_toolroom].append(row)
                
                cur.execute("UPDATE admin SET WAITING_TIME = ? WHERE PART_NAME = ?", (current_waiting_time, row[0]))
    

     if request.form.get('addedoperation'):
             addedoperation=request.form.get('addedoperation')
             print(addedoperation)
             partname2 = request.form.get('partname2')
             cur.execute("UPDATE admin SET OPERATION_NAMES = ? WHERE PART_NAME = ?", [ addedoperation, partname2])
    
             operation_name2 = request.form.get('addoperationName')
             print(operation_name2)
             new_operation_name = request.form.get('addedoperation')
             print(new_operation_name)
                
                # get the part master record
             cur.execute(f"SELECT operation FROM PART_MASTER WHERE PART_NAME = ?", [partname2])
             operation_json = cur.fetchone()[0]
             operation_data = json.loads(operation_json)

             operation_record = None
             for record in operation_data:
                if record['process'] == operation_name2:
                    operation_record = record
                    break

             operation_time_str = operation_record['time']
             operation_time = int(operation_time_str)

             cur.execute(f"SELECT INSPECTION_TIME FROM admin WHERE PART_NAME = ?", [partname2])

             inspection_time_str = cur.fetchone()[0]

                # convert inspection_time_str to datetime object
             inspection_time = dt.datetime.strptime(inspection_time_str, '%H:%M:%S')


                
                # add operation time from inspection time
             new_inspection_time = inspection_time + dt.timedelta(minutes=operation_time)
             
                # convert new_inspection_time back to string
             new_inspection_time_str = new_inspection_time.strftime('%H:%M:%S')
             print(new_inspection_time_str)
             cur.execute(f"UPDATE admin SET INSPECTION_TIME = ? WHERE PART_NAME = ?", [new_inspection_time_str, partname2])
                
                    
             toolroom_dict = defaultdict(list)

                    

             rows = cur.execute("SELECT * FROM admin WHERE STATUS = 'Approved'").fetchall()
             prev_waiting_time = None

             for row in rows:
              current_toolroom = row[7]
              current_waiting_time = None
    
              if current_toolroom not in toolroom_dict:
        # This is the first part we're seeing from this toolroom
               toolroom_dict[current_toolroom].append(row)
              else:
               prev_parts_from_toolroom = toolroom_dict[current_toolroom]
               prev_matching_parts = [prev_row for prev_row in prev_parts_from_toolroom if prev_row[0] != row[0] and prev_row[7] == current_toolroom]
        
               if prev_matching_parts:
            # There are previous parts from the same toolroom, calculate waiting time
                  prev_part = prev_matching_parts[-1]
                  prev_waiting_time = prev_part[5]
                  prev_inspection_time = prev_part[6]
                  prev_intime = prev_part[2]
                  prev3_time = None
                  if prev_part[4] is not None:
                      hello=cur.execute("SELECT WAITING_TIME FROM admin WHERE PART_NAME=? ",(prev_part[0],)).fetchone()[0]
                      prev3_time = datetime.strptime(hello, "%H:%M:%S").time()

                  prev4_time = datetime.strptime(prev_part[3], "%H:%M:%S").time()
                  if prev3_time is not None:
                   time_diff = (datetime.combine(date.today(), prev3_time) - datetime.min)+(datetime.combine(date.today(), prev4_time) - datetime.min) -(datetime.strptime(row[2], '%H:%M:%S') - datetime.strptime(prev_intime, '%H:%M:%S') )
                  else :
                   time_diff = (datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') -datetime.strptime(prev_intime, '%H:%M:%S'))
                    
                  time_diff_seconds = int(time_diff.total_seconds())
                  current_waiting_time = datetime.utcfromtimestamp(time_diff_seconds).strftime('%H:%M:%S')
            
               else:
            # No previous parts from this toolroom, waiting time is None
                current_waiting_time = None
        
        # Append the current part to the list of parts from this toolroom
               toolroom_dict[current_toolroom].append(row)

              cur.execute("UPDATE admin SET WAITING_TIME = ? WHERE PART_NAME = ?", (current_waiting_time, row[0]))
    
   

    conn.commit()
    return render_template('operation.html', PART_MASTER=results, partid=partid)

@app.route('/dashboard/<toolroom>', methods=['GET', 'POST'])
@login_required
def dashboard(toolroom):
  
#  loginroom=session.get('loginroom')
#  if loginroom:
 if 'toolroomsess' in session and session['toolroomsess'] == toolroom:
  conn = sqlite3.connect('part.db')
  conn.row_factory = sqlite3.Row
 
  cur= conn.cursor()



 
  partid = (session['partid'])

  cur.execute("SELECT DATE, MODEL_ID, PART_ID_NAME ,CREATE_DATE, SHEET_NAME, PART_NUMBER, EXCEL_FIELD, ID, UPDATE_BY FROM PART_MASTER WHERE PART_NAME = ?  ",[partid])
  results= cur.fetchall()
 
  cur.execute("SELECT * FROM SECTION_MASTER ")
  results2= cur.fetchall()
  cur.execute("SELECT * FROM MACHINE_MASTER ")
  results3= cur.fetchall()
  cur.execute("SELECT COUNT(*) FROM admin")
  count = cur.fetchone()[0]
  cur.execute(f"SELECT operation FROM PART_MASTER WHERE PART_NAME = ?", [partid])
  operation_json = cur.fetchone()[0]
    # Parse the operation JSON data
  operation_data = json.loads(operation_json)
  if count == 0:
    last_id = 0
  else:
    cur.execute("SELECT ID FROM admin ORDER BY ID DESC LIMIT 1")
    last_id = cur.fetchone()[0]

  new_id = last_id + 1

  if request.method == "POST":
   formatted_operation_time = None  
 

   if request.form.get("selected_options[]"):
    selected_options = request.form.getlist('selected_options[]')
    selected_options_str = ', '.join([f"'{option}'" for option in selected_options])

    # Get the operation JSON data from part_master table
    
   
    
    # Create a dictionary mapping process id to process name and time
    process_map = {data['processesid']: {'process': data['process'], 'time': data['time']} for data in operation_data}
    
    # Get the process names and times based on selected process ids
    process_names = []
    selected_process_time = timedelta()
    for option in selected_options:
        process_id = int(option)
        if process_id in process_map:
            process_names.append(process_map[process_id]['process'])
            time_in_minutes = int(process_map[process_id]['time'])
            operation_time = timedelta(minutes=time_in_minutes)
            selected_process_time += operation_time
            
    # Join the process names as a comma-separated string
    operation_names = ', '.join(process_names)
    session[f'selected_options_{partid}'] = operation_names
    
    # Convert the total operation time to HH:MM:SS format
    formatted_operation_time = str(selected_process_time).split('.')[0]
    session['formatted_operation_time'] = formatted_operation_time

    return operation_names
 
  if request.form.get("submit"):
  
           

            comment = (session['comment'])
            partid = (session['partid'])
            formatted_operation_time = session.get('formatted_operation_time')  # retrieve from session
            priority = (session['priority'])
            selected_options = session.get(f'selected_options_{partid}')
            selected_options_str = selected_options
            section = request.form.get("section")
            machine_req = request.form.getlist('machine[]')
            machine = ', '.join([f"'{option}'" for option in machine_req])
           
           
            cur.execute("INSERT INTO operation_master (PART_NAME,SECTION_CODE,MACHINE_NO)""VALUES (?,?,?)", [partid,section,machine])

            cur.execute("INSERT INTO admin (ID, PART_NAME, COMMENT, TOOLROOM, PRIORITY, OPERATION_NAMES,STATUS) "
                "VALUES (?, (SELECT PART_NAME FROM PART_MASTER WHERE PART_NAME=?), ?, ?, ?, ?,?)",
                [new_id, partid, comment, toolroom, priority, selected_options_str,'Not Approved'])

            cur.execute("UPDATE admin SET INTIME = time('now','localtime') WHERE PART_NAME = ?" ,[partid])
          
            cur.execute("UPDATE admin SET INSPECTION_TIME = ? WHERE PART_NAME = ?", [formatted_operation_time, partid])
            conn.commit()


            


            toolroom_dict = defaultdict(list)

           

            rows = cur.execute("SELECT * FROM admin").fetchall()
            prev_waiting_time = None

            for row in rows:
             current_toolroom = row[7]
             current_waiting_time = None
    
             if current_toolroom not in toolroom_dict:
        # This is the first part we're seeing from this toolroom
              toolroom_dict[current_toolroom].append(row)
             else:
              prev_parts_from_toolroom = toolroom_dict[current_toolroom]
              prev_matching_parts = [prev_row for prev_row in prev_parts_from_toolroom if prev_row[0] != row[0] and prev_row[7] == current_toolroom]
        
              if prev_matching_parts:
            # There are previous parts from the same toolroom, calculate waiting time
                 prev_part = prev_matching_parts[-1]
                 prev_waiting_time = prev_part[5]
                 prev_inspection_time = prev_part[6]
                 prev_intime = prev_part[2]
                 prev3_time = None
                 if prev_part[4] is not None:
                    prev3_time = datetime.strptime(prev_part[4], "%H:%M:%S").time()

                 prev4_time = datetime.strptime(prev_part[3], "%H:%M:%S").time()
                 if prev3_time is not None:
                  time_diff =  (datetime.combine(date.today(), prev3_time) - datetime.min)+(datetime.combine(date.today(), prev4_time) - datetime.min) -(datetime.strptime(row[2], '%H:%M:%S') - datetime.strptime(prev_intime, '%H:%M:%S'))
                 else :
                  time_diff = (datetime.combine(date.today(), prev4_time) - datetime.min)-(datetime.strptime(row[2], '%H:%M:%S') -datetime.strptime(prev_intime, '%H:%M:%S'))
                    
                 time_diff_seconds = int(time_diff.total_seconds())
                 current_waiting_time = datetime.utcfromtimestamp(time_diff_seconds).strftime('%H:%M:%S')
            
              else:
            # No previous parts from this toolroom, waiting time is None
               current_waiting_time = None
        
        # Append the current part to the list of parts from this toolroom
              toolroom_dict[current_toolroom].append(row)

             cur.execute("UPDATE admin SET WAITING_TIME = ? WHERE PART_NAME = ?", (current_waiting_time, row[0]))
             session['loginroom']=False
            conn.commit()
            del session['toolroomsess']         
            return redirect(url_for('login', toolroom=toolroom))

    
 else:
    return redirect(url_for('login', toolroom=toolroom))
 
   
 
     
 conn.commit()  
 

 return render_template('dashboard.html', PART_MASTER=results, SECTION_MASTER=results2,MACHINE_MASTER=results3,new_id=new_id, toolroom=toolroom, operation_data=operation_data)
 
 

@ app.route('/Toolroomregister', methods=['GET', 'POST'])
def toolreg():
 conn = sqlite3.connect('part.db')
 conn.row_factory = sqlite3.Row
   
 cur = conn.cursor()
 cur.execute("SELECT * FROM TOOLROOM_MASTER")
 results = cur.fetchall()
 if request.method == "POST":

    tool_user = request.form.get('tooluser')
    tool_password = request.form.get('tooladminpassword')
    tool_num = request.form.get('toolnum')
    print(tool_num)

    # Check if tool_user or tool_num is already present in TOOLROOM_ADMIN table
    cur.execute(f"SELECT * FROM TOOLROOM_ADMIN WHERE user='{tool_user}' OR toolroom='{tool_num}'")
    result = cur.fetchone()

    if result:
        flash('Username or Toolroom already exists. Please choose a different one.')
        print("fail")
    else:
        # Hash the tool_password before storing it in the database
        hashed_password = bcrypt.generate_password_hash(tool_password).decode('utf-8')

        # Insert a new entry in the TOOLROOM_ADMIN table
        cur.execute(f"INSERT INTO TOOLROOM_ADMIN (user, password, toolroom) VALUES ('{tool_user}', '{hashed_password}', '{tool_num}')")
        print("sucess")
        return redirect(url_for('admindiscovery'))

        # flash('Toolroom registration successful. Please log in.')

 conn.commit()  


 return render_template('toolregister.html',results=results)
 
 

@app.route('/Toolroomlogin', methods=['GET', 'POST'])
def toollogin():
    conn = sqlite3.connect('part.db')
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    cur.execute("SELECT * FROM TOOLROOM_MASTER")
    results = cur.fetchall()

    if request.method == "POST":
        tool_user = request.form.get('tooluser')
        tool_password = request.form.get('tooladminpassword')
        toolroom = request.form.get('toolnum')
        session['toolroomadmin'] = toolroom

        print(toolroom)

        # Check if tool_user and tool_num match the stored hashed password in the database
        cur.execute(f"SELECT * FROM TOOLROOM_ADMIN WHERE user='{tool_user}' AND toolroom='{toolroom}'")
        result = cur.fetchone()

        if result:
            hashed_password = result['password']
            if bcrypt.check_password_hash(hashed_password, tool_password):
                flash('Login successful. Access granted.')
                return redirect(url_for('toolroomadmin', toolroom=toolroom))

            else:
                flash('Incorrect password. Please try again.')
        else:
            flash('Invalid username or toolroom. Please try again.')

    return render_template('toolroomlogin.html', results=results)

 






@ app.route('/register', methods=['GET', 'POST'])
def register():
   form = RegisterForm()
 
   if form.validate_on_submit():
       hashed_password = bcrypt.generate_password_hash(form.password.data)
       new_user = User(username=form.username.data, password=hashed_password)
       db.session.add(new_user)
    #    db.session.begin(subtransactions=True)
       db.session.begin_nested()

       db.session.commit()
       return redirect(url_for('admin'))
 
   return render_template('register.html', form=form)
 
 
if __name__ == "__main__":
   app.run(debug=True)

