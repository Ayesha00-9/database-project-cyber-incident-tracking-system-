from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['DEBUG'] = True

def get_db_connection():
    try:
        return psycopg2.connect(
            host="localhost",
            port="5432",
            dbname="Cybersecurity_db",
            user="postgres",
            password="root"
        )
    except Exception as e:
        print(f"Database Connection Error: {e}")
        return None

@app.route('/')
def index():
    if 'user_id' not in session:
        flash('Please log in first.', 'info')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed!', 'error')
        return redirect(url_for('login'))
    
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents")
    incidents = cursor.fetchall()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    
    cursor.close()
    conn.close()
    return render_template('index.html', user_name=session.get('user_name'), incidents=incidents, users=users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        if not full_name or not email or not password or not role:
            flash("All fields are required.", 'error')
            return render_template('register.html')
        
        password_hash = generate_password_hash(password)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (full_name, email, role, password_hash) VALUES (%s, %s, %s, %s)",
            (full_name, email, role, password_hash)
        )
        conn.commit()
        cursor.close()
        conn.close()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user and check_password_hash(user[4], password):  
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        flash('Invalid credentials!', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/add-incident-user', methods=['POST'])
def add_incident_user():
    incident_title = request.form['incident_title']
    incident_description = request.form['incident_description']
    incident_severity = request.form['incident_severity']
    incident_reporter = request.form['incident_reporter']
    
    user_name = request.form['user_name']
    user_email = request.form['user_email']
    user_role = request.form['user_role']
    password = request.form.get('user_password')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO incidents (title, description, severity, status, reporter_id) VALUES (%s, %s, %s, %s, %s)",
                   (incident_title, incident_description, incident_severity, 'Open', incident_reporter))
    
    cursor.execute("SELECT * FROM users WHERE email = %s", (user_email,))
    if not cursor.fetchone():
        hashed_password = generate_password_hash(password or "default_password")
        cursor.execute("INSERT INTO users (full_name, email, role, password_hash) VALUES (%s, %s, %s, %s)",
                       (user_name, user_email, user_role, hashed_password))
    conn.commit()
    cursor.close()
    conn.close()
    flash('Incident and user added successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/resolve-incident/<int:incident_id>', methods=['POST'])
def resolve_incident(incident_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE incidents SET status = %s WHERE id = %s", ('Resolved', incident_id))
    conn.commit()
    cursor.close()
    conn.close()
    flash('Incident resolved!', 'success')
    return redirect(url_for('index'))

@app.route('/delete-incident/<int:incident_id>', methods=['POST'])
def delete_incident(incident_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM incidents WHERE id = %s", (incident_id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash('Incident deleted!', 'success')
    return redirect(url_for('index'))

@app.before_request
def require_login():
    if 'user_id' not in session and request.endpoint not in ['login', 'register']:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)

