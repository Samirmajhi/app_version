from flask import Flask, request

import mysql.connector

app = Flask(__name__)
conn = mysql.connector.connect(
    host="localhost",
    user="fishtail_123",
    password="#fishtail@This7",
    database="fishtail_user"
)


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

@app.route('/search', methods=['POST'])
def search_products():
    cursor = conn.cursor()
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

if __name__ == '__main__':
    app.run(debug=True)
