from flask import Flask, request, jsonify
import mysql.connector

app = Flask(__name__)
conn = mysql.connector.connect(
    host="localhost",
    user="fishtail_123",
    password="#fishtail@This7",
    database="fishtail_user"
)

@app.route('/add_product', methods=['POST'])
def add_product():
    cursor = conn.cursor()
    ean = request.form['ean']
    name = request.form['name']
    status = request.form['status']
    try:
        sql = "INSERT INTO products_info (EAN_13, Product_Name, Status) VALUES (%s, %s, %s)"
        cursor.execute(sql, (ean, name, status))
        conn.commit()
        return "Data Added Successfully"
    except mysql.connector.Error as err:
        if err.errno == 1062:  # Duplicate entry error code
            return "The Entered EAN_13 Already Exists"
        else:
            return "Couldn't Add Data"

if __name__ == '__main__':
    app.run(debug=True)
