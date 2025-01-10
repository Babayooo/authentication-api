from flask import Flask, request, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from uuid import uuid4
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

def user_id():
    return uuid4().hex

app = Flask(__name__)
app.config ["MAIL_SERVER"]= "smtp.gmail.com"
app.config["MAIL_PORT"]= 465
app.config["MAIL_USERNAME"]= "martinmarto051@gmail.com"
app.config["MAIL_PASSWORD"]= "use the above email to contact me for gigs"
app.config["MAIL_USE_TLS"]= False
app.config["MAIL_USE_SSL"]= True
app.config["MAIL_DEFAULT_SENDER"]= app.config["MAIL_USERNAME"]
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///authentication.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]= False
app.config["SQLALCHEMY_ECHO"]= True
app.config["JWT_SECRET_KEY"]= "kenyahuan1"

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
jwt= JWTManager(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config["JWT_SECRET_KEY"])

class Users(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=user_id)
    username = db.Column( db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable= False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    is_verified = db.Column(db.Boolean, default= False)
    
@app.route("/auth/Register", methods =["POST"])
def register_user():
    try:
        data = request.get_json()
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        
        required_fields = ["username","email","password"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error":f"{field} is required"}), 400
        
        user = Users.query.filter_by(username=username).first()
        
        if user:
            return jsonify({"error":"username already exists"}), 400
        
        user = Users.query.filter_by(email=email).first()
        if user:
            return jsonify({"error": "email already exists"}), 400
        
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            
        new_user = Users(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
    
        token = s.dumps(email, salt="random number")
        url = url_for("register_user", token=token, _external=True)
        
        msg= Message("confirm your email", sender = app.config["MAIL_DEFAULT_SENDER"], recipients=[new_user.email])
        msg.body = f"click the link to verify youe email: {url}"
        mail.send(msg)

        return jsonify({"message":"user created successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error":str(e)}), 500

@app.route("/auth/Register/<token>", methods=["GET"])
def email_verification(token):
    try:
        email= s.loads(token, salt="random number", max_age=3600)
    except SignatureExpired:
        return jsonify({"error": "the token has expired"}), 400
    except BadSignature:
        return jsonify({"error": "invalid token"}), 400
    
    user = Users.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error":"user not found"}), 404
    
    if user.is_verified:
        return jsonify({"error":"email is already verified"}), 400
    user.is_verified = True
    db.session.commit()
    
    return jsonify({"message": "verified"}), 200

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    
    required_fields = ["username", "password"]
    for field in required_fields:
       if field not in data:
           return jsonify({"error": f"{field} is  required"})
    
    user = Users.query.filter_by(username=username).first()
    
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error":"invalid username or passwors"}), 401
    
    if user.is_verified == False:
        return jsonify({"error": "email is not verified please check your email for verification link"}), 401
    
    access_token = create_access_token(identity=user.id)
    
    return jsonify({"id": user.id, "username":user.username, "token": access_token}), 200

@app.route("/account", methods=["GET"])
@jwt_required()
def account():
    user = get_jwt_identity()
    return jsonify({"user":user})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)