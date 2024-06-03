from flask import Flask, request, jsonify, redirect

import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
conn = mysql.connector.connect(
    host="localhost",
    user="fishtail_123",
    password="#fishtail@This7",
    database="fishtail_user"
)

@app.route('/', methods=['POST'])
def signup_or_login():
    cursor = conn.cursor()
    if request.method == 'POST':
        if 'Signup' in request.form:
            first_name = request.form['FirstName']
            last_name = request.form['LastName']
            email = request.form['Email']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            
            errors = []
            if not first_name:
                errors.append("First Name is Required")
            if not last_name:
                errors.append("Last Name is Required")
            if not email:
                errors.append("Email is Required")
            elif not '@' in email or '.' not in email:
                errors.append("Email Format is Invalid!")
            if not password:
                errors.append("Password is Required")
            elif len(password) < 8 or not any(char.isupper() for char in password) or not any(char in '!@#$%^&*()-=+{};:,<.>/' for char in password):
                errors.append("Password should be 8 character long, should contain at least one uppercase letter and one special character!")
            if not confirm_password:
                errors.append("Please Rewrite your password")
            elif password != confirm_password:
                errors.append("Passwords do not match")
            
            if not errors:
                hashed_password = generate_password_hash(password)
                sql = "INSERT INTO Users (FirstName, LastName, email, password) VALUES (%s, %s, %s, %s)"
                cursor.execute(sql, (first_name, last_name, email, hashed_password))
                conn.commit()
                return redirect("fiishtail_warehouse.html")
            else:
                return jsonify(errors=errors), 400
        
        elif 'Email' in request.form and 'Password' in request.form:
            email = request.form['Email']
            password = request.form['Password']
            errors = []
            sql = "SELECT password FROM Users WHERE email=%s"
            cursor.execute(sql, (email,))
            result = cursor.fetchone()
            if result:
                stored_password = result[0]
                if check_password_hash(stored_password, password):
                    return redirect("fiishtail_warehouse.html")
                else:
                    errors.append("Password doesn't Match")
            else:
                errors.append("User not found")
            return jsonify(errors=errors), 400
    
    return "All fields are Required"

if __name__ == '__main__':
    app.run(debug=True)
