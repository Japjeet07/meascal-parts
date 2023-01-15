from flask import Flask, render_template, url_for, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import sqlite3
 
 
conn = sqlite3.connect('menu.db')
conn.row_factory = sqlite3.Row
print("opened successfully")
 
cur= conn.cursor()
 
 
app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
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
   username = db.Column(db.String(20), nullable=False, unique=True)
   password = db.Column(db.String(80), nullable=False)
 
 
 
class RegisterForm(FlaskForm):
   username = StringField(validators=[
                          InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
 
   password = PasswordField(validators=[
                            InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
 
   submit = SubmitField('Register')
 
   def validate_username(self, username):
       existing_user_username = User.query.filter_by(
           username=username.data).first()
       if existing_user_username:
           raise ValidationError(
               'That username already exists. Please choose a different one.')
 
 
class LoginForm(FlaskForm):
   username = StringField(validators=[
                          InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
 
   password = PasswordField(validators=[
                            InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
 
   submit = SubmitField('Login')
 
 
 
 
@app.route('/', methods=['GET', 'POST'])
def login():
   form = LoginForm()
   if form.validate_on_submit():
       
       user = User.query.filter_by(username=form.username.data).first()
       print(User.query.filter_by(username=form.username.data).first())
       if user:
           
           if bcrypt.check_password_hash(user.password, form.password.data):
               login_user(user)
               if request.method == "POST":
                 session["username"] = request.form.get("username")
                
               
               return redirect(url_for('dashboard'))
 
 
   return render_template('login.html', form=form)
 
 
 
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
  
   conn = sqlite3.connect('menu.db')
   conn.row_factory = sqlite3.Row
  
   cur= conn.cursor()
   sql = ("""SELECT * FROM menu""")
  
  
 
   cur.execute(sql)
   results= cur.fetchall()
 
 
   if request.method == 'POST':
    
        quantity1 = request.form['quantity1']
        quantity2 = request.form['quantity2']
        quantity3 = request.form['quantity3']
        quantity4 = request.form['quantity4']
        quantity5 = request.form['quantity5']
        quantity6 = request.form['quantity6']
 
        
       
       
        with sqlite3.connect("menu.db") as con:
           cur = con.cursor()
           print("hi")
      
         
          
           cur.execute("UPDATE menu SET quantity=? WHERE sno=1 ", [quantity1])
           cur.execute("UPDATE menu SET quantity=? WHERE sno=2 ", [quantity2])
           cur.execute("UPDATE menu SET quantity=? WHERE sno=3",  [quantity3])
           cur.execute("UPDATE menu SET quantity=? WHERE sno=4", [quantity4])
           cur.execute("UPDATE menu SET quantity=? WHERE sno=5", [quantity5])
           cur.execute("UPDATE menu SET quantity=? WHERE sno=6", [quantity6])
 
          
          
           
          
 
             
          
        con.commit()
          
    
    
   
        return redirect('/total')
        
       
 
  
 
   return render_template('dashboard.html', menu=results)
 
 
 
 
 
  
 
 
 
   
 
@app.route('/total', methods=['GET', 'POST'])
@login_required
def total():
    conn = sqlite3.connect('menu.db')
    conn.row_factory = sqlite3.Row
    
     
    cur= conn.cursor()
    sql = ("""SELECT `food item`,`quantity`  FROM menu WHERE quantity>0""")
  
  
 
    cur.execute(sql)
    results= cur.fetchall()  
 
 
  
    
 
    data=cur.execute("SELECT * FROM menu")
    
    row2=0
    for row in data:
       row1=row[2]*row[3]
       row2=row2+row1
      
 
       conn.commit()
      
      
 
    
           
 
 
    
    return render_template('total.html', row2=row2, menu=results)
    
 
      
 
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

