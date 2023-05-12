from flask import Flask, request, jsonify, render_template,redirect,url_for,session
import jinja2
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_session import Session
import json


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vaccine_booking.db' # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
app.secret_key = 'mysecretkey' # Secret key for session management
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.app_context().push() #

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    bookings = db.relationship('Booking', backref='user')

    def __repr__(self):
        return f'<User {self.username}>'

    # Required methods for Flask-Login
    def get_id(self):
        return str(self.id)

    @staticmethod
    def get_user_by_username(username):
        return User.query.filter_by(username=username).first()

# Vaccination Centre model
class VaccinationCentre(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    opening_time = db.Column(db.DateTime, nullable=False)
    closing_time = db.Column(db.DateTime, nullable=False)
    available_slots = db.Column(db.JSON)
    bookings = db.relationship('Booking', backref='vc')

    def __repr__(self):
        return f'<VaccinationCentre {self.name}>'

# Booking model
class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vaccination_centre_id = db.Column(db.Integer, db.ForeignKey('vaccination_centre.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False),
    slot_time = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'<Booking {self.slot_time} at {self.vaccination_centre.name}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

FirstAdmin = User(id=1,username="admin",password = bcrypt.generate_password_hash("secretkey").decode('utf-8'), is_admin=True)


# User registration route
@app.route('/signup',methods=['GET'])
def signupform():
    return render_template('UserSignup.html')

#User Login
@app.route('/',methods=['GET','POST'])
@app.route('/login',methods=['GET','POST'])
def loginform():
    return render_template('UserLogin.html')

#Registration Validation
@app.route('/register', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        username = request.form.get('username')
        session['username'] = username
        password = request.form.get('password')
        if not username or not password :
            return jsonify({'error': 'All details are required'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 409
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return "User Registered, Please log in"
    if request.method == "GET":
        return redirect(url_for('signupform'))

#User Login
@app.route('/',methods=['GET','POST'])
@app.route('/login',methods=['GET','POST'])
def userloginform():
    return render_template('UserLogin.html')

# Validating Login
@app.route('/loginvalidate', methods=['POST','GET'])
def login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            return jsonify({'error': 'Invalid username or password'}), 401
        login_user(user) # Logs in the user
        return render_template("slot.html")
    else:
        return redirect(url_for('userloginform'))

#User apply for slot route
@app.route('/bookslot', methods=['POST','GET']) #button
@login_required
def selectslot():
    session['slot'] = request.form.get('slot')
    return ()

@app.route('/availvaccinationcenter', methods=['POST','GET']) #selection
@login_required
def availvc():
    slot = session.get('slot',None)
    vaccination_centres = VaccinationCentre.query.all()
    response = []
    for vc in vaccination_centres:
        if vc.opening_time< slot < vc.closing_time or vc.closing_time < slot < vc.opening_time:
            response.append({
            'id': vc.id,
            'name': vc.name,
            'loc': vc.location,
            'ot': vc.opening_time,
            'ct': vc.closing_time,
            'slot': vc.available_slots
            })
    return render_template('centre.html',response=response)

@app.route('/selectdate', methods=['POST',"GET"]) #button
def selectvc():
    if request.method == "POST":
        session['vc'] = request.form.get('vc') 
    return render_template('date.html')

@app.route('/date',methods=['POST','GET']) #
def selectdate():
    session['date'] = request.form.get('date')
    return redirect(url_for('finalbooking'))

@app.route('/book', methods=['POST','GET']) #button
def finalbooking():
    slot = session.get('slot',None)
    vc = session.get('vc',None)
    date = session.get('date',None)
    v = VaccinationCentre.query.filter_by(name=vc).first()
    if v.available_slots[date] <= 0:
        return "No slots available on this date at this centre"
    if date not in v.available_slots:
        booking = Booking(user_id=current_user.id, vaccination_centre_id=v.id, date=date, slot_time=slot)
        v.available_slots[date] = 9
        db.session.add(booking)
        db.session.commit()
    if v.available_slots[date]>0:
        booking = Booking(user_id=current_user.id, vaccination_centre_id=v.id, date=date, slot_time=slot)
        v.available_slots[date] -= 1
        db.session.add(booking)
        db.session.commit()
    return('booking confirmed')

#User logout 
@app.route('/logout', methods=['POST','GET'])
@login_required
def logout():
    logout_user() # Logs out the user
    return redirect(url_for('userloginform'))

#---------ADMIN-----------

#Admin Loginform
@app.route('/admin/loginform',methods=['GET','POST'])
def adminloginform():
    return render_template('AdminLogin.html')

#Admin Login Validation
@app.route('/admin/login', methods=['POST','GET'])
def admin_login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        if username == FirstAdmin.username and bcrypt.check_password_hash(FirstAdmin.password, password):
            login_user(FirstAdmin)
            return render_template('AdminFunctions.html')
            
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        user = User.query.filter_by(username=username).first()
        if not FirstAdmin or not user or bcrypt.check_password_hash(user.password, password) or not user.is_admin:
            return jsonify({'error': 'Invalid username or password'}), 401
        login_user(user) # Logs in the user
        current_user.is_authenticated = True
        return render_template('AdminFunctions.html')
    if request.method == "GET":
        return redirect(url_for('adminloginform'))

#Admin Signup Form
@app.route('/admin/signup',methods=['GET','POST'])
@login_required
def adminsignupform():
    return render_template('AdminSignUp.html')

#Admin Register
@app.route('/admin/register', methods=['POST','GET'])
@login_required
def adminregister():
    if not current_user.is_admin:
        return jsonify({'error': 'You do not have admin privileges'}), 401
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password, is_admin=True)
        db.session.add(user)
        db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

#Display All Bookings
@app.route('/admin/AllBookings', methods=['POST','GET'])
@login_required
def display_all_bookings():
    if not current_user.is_admin:
        return jsonify({'error': 'Only admin can perform this action'}), 401
    bookings = Booking.query.all()
    response = []
    for b in bookings:
        user = User.query.filter_by(id=b.user_id).first()
        vc = VaccinationCentre.query.filter_by(id=b.vaccination_centre_id).first()
        response.append({
        'id': b.id,
        'name': user.username,
        'loc': vc.name +", " + vc.location,
        'slot': b.slot_time})
    return render_template('DisplayAllBookings.html',response=response)

#Display all centres
@app.route('/admin/DisplayCenters',methods=['GET','POST'])
@login_required
def vaccination_centres():
    vaccination_centres = VaccinationCentre.query.all()
    response = []
    for vc in vaccination_centres:
        if vc.available_slots > 0:
            response.append({
            'id': vc.id,
            'name': vc.name,
            'loc': vc.location,
            'ot': vc.opening_time,
            'ct': vc.closing_time,
            'slot': vc.available_slots
            })
    return render_template('VaccinationCentres.html', response = response)

#Add New Center
@app.route('/admin/add_vaccination_centre', methods=['POST','GET'])
@login_required
def add_vaccination_centre():
    if not current_user.is_admin:
        return jsonify({'error': 'Only admin can perform this action'}), 401
    if request.method == "POST":
        name = request.form.get('name')
        location = request.form.get('location')
        opening_time = request.form.get('opening_time')
        closing_time = request.form.get('closing_time')
        available_slots = {}
        if not name or not location or not opening_time or not closing_time:
            return jsonify({'error': 'All fields are required'}), 400
        vc = VaccinationCentre(name=name, location=location, opening_time=opening_time, closing_time=closing_time, available_slots=json.dump(available_slots))
        db.session.add(vc)
        db.session.commit()
    return redirect(url_for('vaccination_centres'))

#Admin get dosage details route
@app.route('/admin/dosage_details', methods=['GET'])
@login_required
def get_dosage_details():
    if not current_user.is_admin:
        return jsonify({'error': 'Only admin can perform this action'}), 401
    dosage_details = db.session.query(VaccinationCentre.name, db.func.count(Booking.id).label('dosage_count')).join(Booking).group_by(VaccinationCentre.name).all()
    response = []
    for dd in dosage_details:
        response.append({
        'vaccination_centre': dd[0],
        'dosage_count': dd[1]
        })
        return jsonify(response), 200
#Admin remove vaccination centre route
@app.route('/admin/remove_vaccination_centre/int:vaccination_centre_id', methods=['DELETE'])
@login_required
def remove_vaccination_centre(vaccination_centre_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Only admin can perform this action'}), 401
    vc = VaccinationCentre.query.get(vaccination_centre_id)
    if not vc:
        return jsonify({'error': 'Invalid vaccination centre ID'}), 400
    db.session.delete(vc)
    db.session.commit()
    return jsonify({'message': 'Vaccination centre removed successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)