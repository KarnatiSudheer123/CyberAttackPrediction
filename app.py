import os
import numpy as np
import pandas as pd
import joblib
from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import re

# --------------------------- 
# 1. Flask App Initialization
# ---------------------------
app = Flask(__name__)

# ---------------------------
# 2. Load Models
# ---------------------------
voting_model_path = "Models/voting_classifier.sav"
scaler_path = "Models/scaler.sav"

voting_clf = joblib.load(voting_model_path)
scaler = joblib.load(scaler_path)

# Label names (adjust if you have them saved)
label_names = {
    0: "BENIGN",
    1: "Bot",
    2: "DDoS",
    3: "DoS GoldenEye",
    4: "DoS Hulk",
    5: "DoS Slowhttptest",
    6: "DoS slowloris",
    7: "Heartbleed",
    8: "Infiltration",
    9: "PortScan"
}

# Feature order — same as training
feature_names = [
    'Active Min', 'Fwd PSH Flags', 'SYN Flag Count', 'Flow Packets/s',
    'Fwd Packets/s', 'Active Mean', 'Active Std', 'Flow IAT Min',
    'Bwd IAT Total', 'URG Flag Count', 'Bwd IAT Std', 'FIN Flag Count',
    'Min Packet Length', 'Down/Up Ratio', 'Total Length of Fwd Packets',
    'Subflow Fwd Bytes', 'PSH Flag Count', 'Bwd IAT Max'
]


# ---------------------------
# 4. Routes
# ---------------------------

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get input features
        input_features = [float(request.form[feat]) for feat in feature_names]
        input_df = pd.DataFrame([input_features], columns=feature_names)
        scaled = scaler.transform(input_df)

        # Predict
        pred = voting_clf.predict(scaled)[0]
        pred_label = label_names.get(int(pred), str(pred))

        # Get confidence score
        confidence = voting_clf.predict_proba(scaled)[0]
        confidence_percentage = round(confidence[int(pred)] * 100, 2)

        return render_template('result.html',
                               prediction_label=pred_label,
                               confidence=confidence_percentage)
    except Exception as e:
        return render_template('result.html',
                               prediction_label="Error",
                               confidence=0)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    else:
        username = request.form.get('user','')
        name = request.form.get('name','')
        email = request.form.get('email','')
        number = request.form.get('mobile','')
        password = request.form.get('password','')

        # Server-side validation
        username_pattern = r'^.{6,}$'
        name_pattern = r'^[A-Za-z ]{3,}$'
        email_pattern = r'^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$'
        mobile_pattern = r'^[6-9][0-9]{9}$'
        password_pattern = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$'

        if not re.match(username_pattern, username):
            return render_template("signup.html", message="Username must be at least 6 characters.")
        if not re.match(name_pattern, name):
            return render_template("signup.html", message="Full Name must be at least 3 letters, only letters and spaces allowed.")
        if not re.match(email_pattern, email):
            return render_template("signup.html", message="Enter a valid email address.")
        if not re.match(mobile_pattern, number):
            return render_template("signup.html", message="Mobile must start with 6-9 and be 10 digits.")
        if not re.match(password_pattern, password):
            return render_template("signup.html", message="Password must be at least 8 characters, with an uppercase letter, a number, and a lowercase letter.")

        con = sqlite3.connect('signup.db')
        cur = con.cursor()
        cur.execute("SELECT 1 FROM info WHERE user = ?", (username,))
        if cur.fetchone():
            con.close()
            return render_template("signup.html", message="Username already exists. Please choose another.")
        
        cur.execute("insert into `info` (`user`,`name`, `email`,`mobile`,`password`) VALUES (?, ?, ?, ?, ?)",(username,name,email,number,password))
        con.commit()
        con.close()
        return redirect(url_for('login'))

@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "GET":
        return render_template("signin.html")
    else:
        mail1 = request.form.get('user','')
        password1 = request.form.get('password','')
        con = sqlite3.connect('signup.db')
        cur = con.cursor()
        cur.execute("select `user`, `password` from info where `user` = ? AND `password` = ?",(mail1,password1,))
        data = cur.fetchone()

        if data == None:
            return render_template("signin.html", message="Invalid username or password.")    

        elif mail1 == 'admin' and password1 == 'admin':
            return render_template("home.html")

        elif mail1 == str(data[0]) and password1 == str(data[1]):
            return render_template("home.html")
        else:
            return render_template("signin.html", message="Invalid username or password.")

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/home')
def home():
	return render_template('home.html')

@app.route('/home1')
def home1():
	return render_template('home1.html')

@app.route('/graphs')
def graphs():
	return render_template('graphs.html')

@app.route('/logon')
def logon():
	return render_template('signup.html')

@app.route('/login')
def login():
	return render_template('signin.html')



# ---------------------------
# 5. Run Server
# ---------------------------
if __name__ == "__main__":
    app.run(debug=True)