from flask import Flask, render_template,redirect, url_for, request, send_from_directory, send_file, jsonify
from flask_cors import CORS
from flask import g
import os
import threading
import cv2 
from pyzbar.pyzbar import decode 
import time
import mysql.connector 
from flask import Flask, request, jsonify, redirect,send_from_directory

import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

CORS(app)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
db_connection = mysql.connector.connect(
    host="localhost",
    user="fishtail_123",
    password='#fishtail@This7',
    port = 3306,
    database="fishtail_user"
)
cursor = db_connection.cursor()


from flask import g

# Function to get the database connection
def get_db():
    if 'db' not in g:
        g.db = mysql.connector.connect(
            host="localhost",
            user="fishtail_123",
            password='#fishtail@This7',
            port=3306,
            database="fishtail_user"
        )
    return g.db
def get_cursor():
    if 'cursor' not in g:
        g.cursor = get_db().cursor()
    return g.cursor

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

selected_status = None

# @app.route('/',methods=['GET'])
# def index():
#     return send_from_directory('static', 'fiishtail_warehouse.html')


@app.route('/', methods=['POST'])
def signup_or_login():
    
    cursor = db_connection.cursor()
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
                db_connection.commit()
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

from flask import jsonify

import logging

# Define a logger
logger = logging.getLogger('product_logger')
logger.setLevel(logging.ERROR)

# Define a file handler
file_handler = logging.FileHandler('product_error.log')
file_handler.setLevel(logging.ERROR)

# Define a formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add the file handler to the logger
logger.addHandler(file_handler)

@app.route('/add_product', methods=['POST'])
def add_product():
    db_connection = mysql.connector.connect(
    host="localhost",
    user="fishtail_123",
    password='#fishtail@This7',
    port = 3306,
    database="fishtail_user"
)

    cursor = db_connection.cursor()
    data = request.get_json()
    EAN_13 = data.get('ean')
    Product_Name = data.get('name')
    
    try:
        sql = "INSERT INTO product_detail (EAN_13, Product_Name) VALUES (%s, %s)"
        cursor.execute(sql, (EAN_13, Product_Name))
        db_connection.commit()
        return jsonify({'success': True, 'message': 'Data Added Successfully'})
    except mysql.connector.Error as err:
        if err.errno == 1062:  # Duplicate entry error code
            error_message = 'The Entered EAN_13 Already Exists'
        else:
            error_message = f'Error: {err.msg}'
        logger.error(error_message)  # Log the error
        return jsonify({'success': False, 'error': error_message}), 400

@app.route('/recent_scans', methods=['GET'])
def get_recent_scans():
    try:
        db_connection = mysql.connector.connect(
    host="localhost",
    user="fishtail_123",
    password='#fishtail@This7',
    port = 3306,
    database="fishtail_user"
)

        cursor = db_connection.cursor(dictionary=True)  # Use dictionary cursor for easier data handling
        query = "SELECT EAN_13, Status FROM products_info ORDER BY timestamp DESC LIMIT 5"
        cursor.execute(query)
        recent_scans = cursor.fetchall()
        db_connection.close()
        return jsonify(recent_scans)
    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'db_connection' in locals():
            db_connection.close()

@app.route('/search', methods=['POST'])
def search_products():
    cursor = db_connection.cursor()
    if request.method == 'POST' and 'search' in request.form:
        search_term = request.form['search']
        sql = "SELECT * FROM products_info WHERE EAN_13 LIKE %s OR Product_Name LIKE %s OR Status LIKE %s"
        cursor.execute(sql, (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
        result = cursor.fetchall()

        if result:
            response = "<h2>Search Results:</h2><ul>"
            for row in result:
                response += f"<li>EAN: {row[0]} - Name: {row[1]} - Status: {row[2]}</li>"
            response += "</ul>"
            return response
        else:
            return "No Results Found"
    else:
        return "Invalid Request"

@app.route('/products', methods=['GET'])  
def get_products():

    db_connection = mysql.connector.connect(
    host="localhost",
    user="fishtail_123",
    password='#fishtail@This7',
    port = 3306,
    database="fishtail_user"
)
    cursor = db_connection.cursor(dictionary=True)
    # SQL query to join products_info with product_detail to get product names
    sql = """
    SELECT 
        products_info.scan_id, 
        products_info.EAN_13, 
        product_detail.Product_Name, 
        products_info.Status, 
        products_info.timestamp, 
        products_info.scan_count
    FROM 
        products_info
    LEFT JOIN 
        product_detail ON products_info.EAN_13 = product_detail.EAN_13
    """
    cursor.execute(sql)
    result = cursor.fetchall()
    db_connection.close()

    if result:
        return jsonify(result)
    else:
        return jsonify([])

@app.route('/set_status', methods=['POST'])  
def set_status():
   global selected_status
   data = request.form
   selected_status = data['selectedStatus']
   print("Received", selected_status)
   return jsonify({'message': 'Status set succesfully'}), 200

# flask for retreiving list of inventories on that day
def get_db_cursor():
   if 'db_cursor' not in g:
      g.db_cursor = db_connection.cursor()
   return g.db_cursor
@app.teardown_appcontext
def close_db(error):
   if 'db_cursor' in g:
      g.db_cursor.close()
@app.route('/get_inventories', methods=['POST'])
def get_inventories():
   data = request.json
   timestamp = data.get('timestamp')
   status = data.get('Status')
   try:
    cursor = get_db_cursor()
    sql_query = "SELECT EAN_13, Status, timestamp, scan_count FROM products_info WHERE DATE(timestamp) = %s AND Status = %s"
    cursor.execute(sql_query, (timestamp, status))
    inventories = cursor.fetchall()
    cursor.close()
    return jsonify({'inventories': inventories}), 200
   except mysql.connector.Error as err:
      print("Error:", err)
      return jsonify({'error': 'Failed to fetch'}), 500

@app.route('/filtered_data()', methods=['POST'])
def filtered_data():
   status = request.args.get('status')
   date = request.args.get('date')
   inventories =[]
   with open('filtered_data.html', 'r') as file:
      html_content = file.read()
      html_content = html_content.replace('{{ status }}', status)
      html_content = html_content.replace('{{ date }}', date)
      inventory_rows = ''.join([f"<tr><td>{inventory['EAN']}<td>{inventory['ScanCount']}</td></tr>" for inventory in inventories])
      html_content = html_content.replace('{{ inventories }}', inventory_rows)
      with open('temp_filtered_data.html', 'w') as temp_file:
         temp_file.write(html_content)
         return send_file('temp_filtered_data.html')
   

def update_product_status(ean_13, status):
   try:
      sql_query = "UPDATE products_info SET Status = %s WHERE EAN_13 = %s"
      cursor.execute(sql_query, (status, ean_13))
      db_connection.commit()
      print("Status updated for product with EAN_13:", ean_13)
   except mysql.connector.Error as err:
      print("Errror:", err)
      db_connection.rollback()


def insert_products_info(ean_13, status, timestamp, scan_count):
    db_connection = mysql.connector.connect(
                host="localhost",
                user="fishtail_123",
                password='#fishtail@This7',
                port = 3306,
                database="fishtail_user"
            )
    try:
    

            
      cursor = db_connection.cursor() 
      
      
      
      
      ean_13_int = int(ean_13)
      sql_insert_query = "INSERT INTO  products_info (EAN_13, Status, Timestamp, Scan_Count) VALUES (%s,%s,%s,%s)"
      sql_check_existing_query = "SELECT COUNT(*) FROM products_info WHERE EAN_13 = %s AND Status = %s"

      cursor.execute(sql_check_existing_query, (ean_13_int, status))
      existing_records_count = cursor.fetchone()[0]

      if existing_records_count >0:
       sql_update_query = "UPDATE products_info SET Scan_Count = Scan_Count + %s WHERE EAN_13 = %s AND Status=%s"
       cursor.execute(sql_update_query, (scan_count, ean_13_int, status))
      else:
       cursor.execute(sql_insert_query, (ean_13_int, status, timestamp, scan_count ))  
      db_connection.commit()
      print("Record inserted/Updated Succesfully")
    except mysql.connector.Error as err:
         if err.errno == 1062:
            sql_update_query = "UPDATE products_info SET Scan_Count = Scan_Count + %s WHERE EAN_13 = %s AND Status = %s"
            cursor.execute(sql_update_query, (scan_count, ean_13_int, status))
            db_connection.commit()
            print("Existing record  updated ")
         else:
             print("Error:", err)
             db_connection.rollback()
    finally:
       cursor.close()

def update_scan_count(ean_13, status, scan_count):
   try:
      sql_update_query = "UPDATE products_info SET Scan_Count = Scan_Count + %s WHERE EAN_13 = %s AND Status=%s"
      cursor.execute(sql_update_query, (scan_count, ean_13, status))
      db_connection.commit()
      print("Updated Scan Count")
   except mysql.connector.Error as err:
      print("Error:", err)
      db_connection.rollback()
    
       
def retreive_product_info(ean_13):
   try:
 
      cursor = db_connection.cursor()
      sql_query = "SELECT * FROM products_info WHERE EAN_13 = %s"
      cursor.execute(sql_query, (ean_13,))
      result = cursor.fetchone()
      cursor.close()
      db_connection.close()
      if result:
       return result
      else:
       return None
   except mysql.connector.Error as err:
      print("Error:", err) 
      return None

import threading
run_camera_thread = True  # Flag to control the camera thread

@app.route('/execute_camera_script', methods=['POST'])
def execute_camera_script():
    print("Camera execution requested")
    global selected_status
    print("selected_status:", selected_status)
    try:
        while selected_status is None:
            time.sleep(0.5)

        camera_status = True
        camera_thread = threading.Thread(target=handle_camera, args=(selected_status, camera_status))
        camera_thread.start()
        return 'Camera executed successfully', 200
    except Exception as e:
        return str(e), 500

def handle_camera(selected_status, camera_status):
    global run_camera_thread
    run_camera_thread = camera_status
    with app.app_context():
        try:
            db_connection = mysql.connector.connect(
                host="localhost",
                user="fishtail_123",
                password='#fishtail@This7',
                port=3306,
                database="fishtail_user"
            )

            cursor = db_connection.cursor()
            cap = cv2.VideoCapture(0)
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            used_codes = set()
            entry_detected = False  # Flag to track if an entry has been detected

            while run_camera_thread:  # Check flag to continue running the thread
                success, frame = cap.read()
                if success:  # Decodes data from frame
                    barcodes = decode(frame)
                    if barcodes:
                        for code in barcodes:
                            decoded_data = code.data.decode('utf-8')
                            if decoded_data not in used_codes:
                                print('Approved, Scanned Code:')
                                print(decoded_data)
                                time.sleep(2)

                                ean_13 = decoded_data
                                product_info = retreive_product_info(ean_13)
                                product_name = 'Unknown'

                                status = selected_status

                                try:
                                    print("Inserting into DB")
                                    print("EAN_13:", ean_13)
                                    print("Status:", status)

                                    cursor.execute("SELECT Status FROM products_info WHERE EAN_13=%s ORDER BY timestamp DESC LIMIT 1", (ean_13,))
                                    current_status = cursor.fetchone()

                                    if current_status:
                                        current_status = current_status[0]
                                        if status == "Examine":
                                            cursor.execute("""
                                                SELECT 
                                                    products_info.scan_id, 
                                                    products_info.EAN_13, 
                                                    product_detail.Product_Name, 
                                                    products_info.Status, 
                                                    products_info.timestamp, 
                                                    products_info.scan_count
                                                FROM 
                                                    products_info
                                                LEFT JOIN 
                                                    product_detail ON products_info.EAN_13 = product_detail.EAN_13
                                                WHERE
                                                    products_info.EAN_13 = %s
                                            """, (ean_13,))

                                            entries = cursor.fetchall()
                                            print("Showing all records for product:", ean_13)
                                            for entry in entries:
                                                print("Result:", entry)
                                                time.sleep(2)
                                            # Set the flag to False to stop the camera thread after examine
                                            run_camera_thread = False
                                            continue

                                        if current_status == "Entry":
                                            entry_detected = True

                                        elif status == "Exit" and not entry_detected:
                                            print("Exit detected but no entry has been detected. Skipping...")
                                            continue

                                        if (status == "Entry" and entry_detected) or (status == "Exit" and entry_detected):
                                            cursor.execute("SELECT * FROM products_info WHERE EAN_13=%s AND Status='Entry'", (ean_13,))
                                            entry_exists = cursor.fetchone()
                                            if entry_exists:
                                                print("Product already scanned as 'Entry'. Allowing 'Exit' scan only.")
                                                status = "Exit"
                                        else:
                                            if status == "Exit":
                                                print("Exit detected but no entry has been detected. Skipping...")
                                                continue
                                    else:
                                        print("No previous status found for product:", ean_13)

                                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                                    scan_count = 1
                                    sql_insert_query = "INSERT INTO products_info (EAN_13, Status, Timestamp, Scan_Count) VALUES (%s, %s, %s, %s)"
                                    cursor.execute(sql_insert_query, (ean_13, status, timestamp, scan_count))
                                    db_connection.commit()
                                    print("Successfully inserted", status)
                                    used_codes.add(decoded_data)
                                    time.sleep(2)

                                    # Set the flag to False to stop the camera thread
                                    run_camera_thread = False

                                except Exception as e:
                                    print("Error:", str(e))
                                    time.sleep(5)
                            else:
                                print('Sorry, this code has been used')
                                product_info = retreive_product_info(decoded_data)
                                if product_info:
                                    print("Result:", decoded_data, product_info[0], product_info[1])
                                    time.sleep(3)
                                else:
                                    time.sleep(5)
                    else:
                        cv2.imshow('Testing-code-scan', frame)
                        cv2.waitKey(1)
                else:
                    cv2.imshow('Testing-code-scan', frame)
                    cv2.waitKey(1)
        except Exception as e:
            print("Error:", str(e))
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'db_connection' in locals():
                db_connection.close()
            if 'cap' in locals():
                cap.release()
                cv2.destroyAllWindows()

if __name__ =='__main__':
   app.run(debug=True)