from flask import Flask, jsonify
import mysql.connector

app = Flask(__name__)
conn = mysql.connector.connect(
    host="localhost",
    user="fishtail_123",
    password="#fishtail@This7",
    database="fishtail_user"
)

@app.route('/products', methods=['GET'])
def get_products():
    cursor = conn.cursor(dictionary=True)
    sql = "SELECT * FROM products_info"
    cursor.execute(sql)
    result = cursor.fetchall()

    if result:
        return jsonify(result)
    else:
        return jsonify([])

if __name__ == '__main__':
    app.run(debug=True)
