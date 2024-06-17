from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myr.db'
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    prenom = db.Column(db.String(80), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    nom = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    
    # Relation avec les groupes où l'utilisateur est membre)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relation avec les utilisateurs membres du groupe
    members = db.relationship('User', secondary='user_groups', backref='member_of_groups')
    
    # Relation avec les messages du groupe
    messages = db.relationship('Message', backref='group', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class UserGroups(db.Model):
    __tablename__ = 'user_groups'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), primary_key=True)

@app.route("/")
def home():
    if len(session) >0:
        username = session['username']
        return render_template("index.html",username=username)
    return render_template("index.html")


@app.route("/login",  methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        
        username = request.form['Username']
        password = request.form['Password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['username'] = user.username
            user.online = True
            db.session.commit()
            return redirect(url_for('chat'))
        return render_template('login.html', error='Invalid Credentials')
    return render_template("login.html")

@app.route("/register",  methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        prenom = request.form['Prenom']
        nom = request.form['Nom']
        age = request.form['Age']
        username = request.form['Username']
        password = request.form['Password']

        print(f"Received data: {prenom}, {nom}, {age}, {username}, {password}")
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error='Username already exists')
        new_user = User(username=username, password=password,prenom =prenom, age=age, nom=nom)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = new_user.username
        new_user.online = True
        db.session.commit()
        return redirect(url_for('chat'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user:
            db.session.commit()
        session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/chat", methods=["POST", "GET"])
def chat():

    if len(session) >0:
        username = session['username']
        return render_template("chat.html",username=username)
    return render_template("chat.html")

@app.route("/account")
def account():
    if len(session) >0:
        user = User.query.filter_by(username=session['username']).first()
        username = session['username']
        return render_template("account.html",username=username, user=user)
    return render_template("account.html")

@app.route('/update_account', methods=['POST'])
def update_account():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user:
            user.prenom = request.form['prenom']
            user.nom = request.form['nom']
            user.age = request.form['age']
            db.session.commit()
            return redirect(url_for('account'))
    return redirect(url_for('login'))

@app.route('/delete_account')
def delete_account():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/apropos")
def apropos():
    if len(session) >0:
        username = session['username']
        return render_template("apropos.html",username=username)
    return render_template("apropos.html")


if __name__ == '__main__':
    app.run(host='192.168.1.20', debug=True)