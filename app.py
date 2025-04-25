from flask import Flask, render_template, request, redirect, session, flash
import os, json, base64, hashlib, random
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# ===== XOR Encryption Setup =====
SECRET_KEY_FILE = "secret.key"
def load_secret_key():
    with open(SECRET_KEY_FILE, 'r') as f:
        return f.read().strip()
SECRET_KEY = load_secret_key()

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def encrypt_data(data: dict) -> str:
    data_bytes = json.dumps(data).encode('utf-8')
    key_bytes = SECRET_KEY.encode('utf-8')
    return base64.b64encode(xor_bytes(data_bytes, key_bytes)).decode('utf-8')

def decrypt_data(encoded_str: str) -> dict:
    try:
        encrypted_bytes = base64.b64decode(encoded_str.encode('utf-8') + b'===')
        key_bytes = SECRET_KEY.encode('utf-8')
        return json.loads(xor_bytes(encrypted_bytes, key_bytes).decode('utf-8'))
    except:
        return {}

CHARGES_FILE = 'charges.json'

def load_charges():
    if not os.path.exists(CHARGES_FILE):
        return {}
    try:
        with open(CHARGES_FILE, 'r') as f:
            encrypted_str = f.read()
        return decrypt_data(encrypted_str)
    except Exception as e:
        print("❌ Failed to load charges:", e)
        return {}

def save_charges(charges):
    with open(CHARGES_FILE, 'w') as f:
        encrypted = encrypt_data(charges)
        f.write(encrypted)

# ===== User Handling =====
USER_DATA_FILE = 'users.json'
def load_users():
    if not os.path.exists(USER_DATA_FILE): return {}
    with open(USER_DATA_FILE, 'r') as f: return decrypt_data(f.read())

def save_users(users):
    with open(USER_DATA_FILE, 'w') as f: f.write(encrypt_data(users))

def hash_password(pw): return hashlib.sha256(pw.encode()).hexdigest()

# ===== Flask Routes =====
@app.route('/')
def home(): return redirect('/login')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        u, p, r = request.form['username'], request.form['password'], request.form['role']
        users = load_users()
        if u in users:
            flash('Username already taken.')
            return redirect('/signup')
        users[u] = {"password": hash_password(p), "role": r}
        save_users(users)
        flash('Account created successfully.')
        return redirect('/login')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    users = load_users()
    attempts = load_login_attempts()

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        now = datetime.now()
        hashed_pw = hash_password(password)

        if username not in users:
            flash("❌ No such user.")
            return redirect('/login')

        user_attempts = attempts.get(username, {"attempts": 0, "last_attempt": None, "log": []})

        # Check for cooldown
        if user_attempts["attempts"] >= 3:
            last_time = datetime.fromisoformat(user_attempts["last_attempt"])
            time_diff = (now - last_time).total_seconds()
            if time_diff < 60:
                remaining = int(60 - time_diff)
                flash(f"⏳ Too many failed attempts. Try again in {remaining} seconds.")
                return redirect('/login')
            else:
                user_attempts["attempts"] = 0
                user_attempts["log"] = []

        # Correct password
        if users[username]['password'] == hashed_pw:
            session['username'] = username
            session['role'] = users[username]['role']
            user_attempts["attempts"] = 0
            user_attempts["log"] = []
            save_login_attempts(attempts)
            return redirect('/verify')

        # Incorrect password
        user_attempts["attempts"] += 1
        user_attempts["last_attempt"] = now.isoformat()
        user_attempts["log"].append({
            "time": now.isoformat(),
            "reason": "Incorrect password"
        })
        attempts[username] = user_attempts
        save_login_attempts(attempts)

        if user_attempts["attempts"] >= 3:
            flash("🚫 Account locked for 1 minute due to 3 failed attempts.")
        else:
            flash(f"❌ Incorrect password. {3 - user_attempts['attempts']} attempt(s) left.")
        return redirect('/login')

    return render_template('login.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'username' not in session: return redirect('/login')
    code = session.get('verify_code') or str(random.randint(100000, 999999))
    session['verify_code'] = code
    if request.method == 'POST':
        if request.form['code'] == session['verify_code']:
            del session['verify_code']
            return redirect('/dashboard')
        flash('Verification failed.')
    return render_template('verify.html', code=code)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session: return redirect('/login')
    role = session['role'].lower()
    return render_template(f'dashboard_{role}.html', username=session['username'], role=role)

@app.route('/availability', methods=['GET', 'POST'])
def availability():
    if 'username' not in session:
        return redirect('/login')

    doctors = {
        "Dr. Smith": ["09:00", "10:00", "11:00", "13:00", "15:00"],
        "Dr. Jones": ["09:00", "10:00", "14:00", "15:00"],
        "Dr. Patel": ["10:00", "11:00", "12:00", "16:00"]
    }

    available_slots = []
    selected_doctor = None
    selected_date = None

    if request.method == 'POST':
        selected_doctor = request.form['doctor']
        selected_date = request.form['date']

        # Get booked slots
        appointments = load_appointments()
        booked = set()
        for appts in appointments.values():
            for a in appts:
                if a['date'] == selected_date and a['doctor'] == selected_doctor:
                    booked.add(a['time'])

        available_slots = [t for t in doctors[selected_doctor] if t not in booked]

    return render_template('availability.html',
                           doctors=doctors,
                           available_slots=available_slots,
                           selected_doctor=selected_doctor,
                           selected_date=selected_date)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/view_profile')
def view_profile():
    if 'username' not in session: return redirect('/login')
    return render_template('view_profile.html', username=session['username'], role=session['role'])

from flask import jsonify

APPOINTMENT_DATA_FILE = 'appointments.json'

def load_appointments():
    if not os.path.exists(APPOINTMENT_DATA_FILE):
        return {}
    with open(APPOINTMENT_DATA_FILE, 'r') as f:
        return decrypt_data(f.read())

def save_appointments(data):
    with open(APPOINTMENT_DATA_FILE, 'w') as f:
        f.write(encrypt_data(data))

# Route to create appointment
@app.route('/create_appointment', methods=['GET', 'POST'])
def create_appointment():
    if 'username' not in session:
        return redirect('/login')

    doctors = {
        "Dr. Smith": ["09:00", "10:00", "11:00", "13:00", "15:00"],
        "Dr. Jones": ["09:00", "10:00", "14:00", "15:00"],
        "Dr. Patel": ["10:00", "11:00", "12:00", "16:00"]
    }

    if request.method == 'POST':
        date = request.form['date']
        doctor = request.form['doctor']
        reason = request.form['reason']
        time = request.form['time']
        username = session['username']

        appointments = load_appointments()
        if username not in appointments:
            appointments[username] = []

        appointments[username].append({
            "title": reason,
            "date": date,
            "time": time,
            "doctor": doctor
        })

        save_appointments(appointments)
        flash("✅ Appointment booked successfully.")
        return redirect('/dashboard')

    return render_template('create_appointment.html', doctors=doctors)

LOGIN_ATTEMPT_FILE = 'login_attempts.json'

def load_login_attempts():
    if os.path.exists(LOGIN_ATTEMPT_FILE):
        try:
            with open(LOGIN_ATTEMPT_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_login_attempts(attempts):
    with open(LOGIN_ATTEMPT_FILE, 'w') as f:
        json.dump(attempts, f)


@app.route('/get_available_times', methods=['POST'])
def get_available_times():
    data = request.get_json()
    date = data['date']
    doctor = data['doctor']
    all_times = {
        "Dr. Smith": ["09:00", "10:00", "11:00", "13:00", "15:00"],
        "Dr. Jones": ["09:00", "10:00", "14:00", "15:00"],
        "Dr. Patel": ["10:00", "11:00", "12:00", "16:00"]
    }
    appointments = load_appointments()
    booked = set()
    for appts in appointments.values():
        for a in appts:
            if a['date'] == date and a['doctor'] == doctor:
                booked.add(a['time'])

    available = [t for t in all_times[doctor] if t not in booked]
    return jsonify(available)
@app.route('/view_my_appointments')
def view_my_appointments():
    if 'username' not in session:
        return redirect('/login')

    username = session['username']
    appointments = load_appointments()
    my_appointments = appointments.get(username, [])

    return render_template('view_my_appointments.html', appointments=my_appointments)

@app.route('/cancel_appointment', methods=['GET', 'POST'])
def cancel_appointment():
    if 'username' not in session:
        return redirect('/login')

    username = session['username']
    appointments = load_appointments()
    user_appts = appointments.get(username, [])

    if request.method == 'POST':
        index = int(request.form['cancel_index'])
        if 0 <= index < len(user_appts):
            removed = user_appts.pop(index)
            flash(f"❌ Appointment on {removed['date']} at {removed['time']} with {removed['doctor']} was canceled.")
            appointments[username] = user_appts
            save_appointments(appointments)
        return redirect('/cancel_appointment')

    return render_template('cancel_appointment.html', appointments=user_appts)

@app.route('/change_appointment', methods=['GET', 'POST'])
def change_appointment():
    if 'username' not in session:
        return redirect('/login')

    username = session['username']
    appointments = load_appointments()
    user_appts = appointments.get(username, [])

    doctors = {
        "Dr. Smith": ["09:00", "10:00", "11:00", "13:00", "15:00"],
        "Dr. Jones": ["09:00", "10:00", "14:00", "15:00"],
        "Dr. Patel": ["10:00", "11:00", "12:00", "16:00"]
    }

    if request.method == 'POST':
        index = int(request.form['index'])
        new_date = request.form['new_date']
        new_doctor = request.form['new_doctor']
        new_time = request.form['new_time']

        # Check availability
        booked = set()
        for appts in appointments.values():
            for a in appts:
                if a['date'] == new_date and a['doctor'] == new_doctor:
                    booked.add(a['time'])

        if new_time not in doctors[new_doctor] or new_time in booked:
            flash("❌ Selected time is not available.")
            return redirect('/change_appointment')

        # Apply changes
        user_appts[index]['date'] = new_date
        user_appts[index]['doctor'] = new_doctor
        user_appts[index]['time'] = new_time
        save_appointments(appointments)
        flash("✅ Appointment successfully changed.")
        return redirect('/change_appointment')

    return render_template('change_appointment.html', appointments=user_appts, doctors=doctors)

PATIENT_VISITS_FILE = 'patient_visits.json'

def load_patient_visits():
    if not os.path.exists(PATIENT_VISITS_FILE):
        return {}
    with open(PATIENT_VISITS_FILE, 'r') as f:
        return decrypt_data(f.read())

@app.route('/view_my_medical_records')
def view_my_medical_records():
    if 'username' not in session:
        return redirect('/login')

    username = session['username']
    visits = load_patient_visits()
    user_visits = visits.get(username, [])

    return render_template('view_my_medical_records.html', visits=user_visits)

@app.route('/create_patient_visit', methods=['GET', 'POST'])
def create_patient_visit():
    if 'username' not in session or session['role'] != 'Staff':
        return redirect('/login')

    visits = load_patient_visits()
    users = load_users()

    if request.method == 'POST':
        patient_username = request.form['username']
        if patient_username not in users or users[patient_username]['role'] != 'Patient':
            flash("❌ No patient found with that username.")
            return redirect('/create_patient_visit')

        visit_data = {
            "name": request.form['name'],
            "address": request.form['address'],
            "phone": request.form['phone'],
            "email": request.form['email'],
            "ssn": request.form['ssn'],
            "insurance": request.form['insurance'],
            "created_by": session['username'],
            "timestamp": datetime.now().isoformat()
        }

        if patient_username not in visits:
            visits[patient_username] = []

        visits[patient_username].append(visit_data)
        with open(PATIENT_VISITS_FILE, 'w') as f:
            f.write(encrypt_data(visits))

        flash("✅ Patient visit created.")
        return redirect('/dashboard')

    return render_template('create_patient_visit.html')

@app.route('/view_all_appointments')
def view_all_appointments():
    if 'username' not in session or session['role'] not in ['Patient', 'Staff', 'Doctor', 'Nurse', 'CEO']:
        return redirect('/login')

    appointments = load_appointments()
    return render_template('view_all_appointments.html', all_appointments=appointments, role=session['role'])

COPAY_FILE = 'copay.json'

def load_copay_data():
    if not os.path.exists(COPAY_FILE):
        return {}
    with open(COPAY_FILE, 'r') as f:
        return decrypt_data(f.read())

def save_copay_data(data):
    with open(COPAY_FILE, 'w') as f:
        f.write(encrypt_data(data))

@app.route('/make_copay', methods=['GET', 'POST'])
def make_copay():
    if 'username' not in session:
        return redirect('/login')
    
    username = session['username']
    charges = load_charges()
    copays = load_copay_data()
    cards = load_card_data()

    total_charged = sum(entry['amount'] for entry in charges.get(username, []))
    total_paid = sum(p['amount'] for p in copays.get(username, []))
    remaining_balance = total_charged - total_paid

    if request.method == 'POST':
        selected_card = request.form['card']
        cvv = request.form['cvv']
        expiry = request.form['expiry']
        amount = float(request.form['amount'])

        user_cards = cards.get(username, {})
        card = user_cards.get(selected_card)

        if not card or card['cvv'] != cvv or card['expiry'] != expiry:
            flash("❌ Card verification failed.")
            return redirect('/make_copay')

        # Save copay
        if username not in copays:
            copays[username] = []
        copays[username].append({
            "amount": amount,
            "timestamp": datetime.now().isoformat()
        })
        save_copay_data(copays)
        flash(f"✅ Copay of ${amount:.2f} processed successfully.")
        return redirect('/make_copay')

    return render_template('make_copay.html',
                           username=username,
                           total_charged=total_charged,
                           total_paid=total_paid,
                           remaining_balance=remaining_balance,
                           cards=cards.get(username, {}))

CARD_DATA_FILE = "cards.json"

def load_card_data():
    if not os.path.exists(CARD_DATA_FILE):
        return {}
    with open(CARD_DATA_FILE, 'r') as f:
        return decrypt_data(f.read())

def save_card_data(data):
    with open(CARD_DATA_FILE, 'w') as f:
        f.write(encrypt_data(data))

@app.route('/manage_cards', methods=['GET', 'POST'])
def manage_cards():
    if 'username' not in session:
        return redirect('/login')
    
    username = session['username']
    cards = load_card_data()
    user_cards = cards.get(username, {})

    if request.method == 'POST':
        if request.form.get('delete_card'):
            card_to_delete = request.form['delete_card']
            if card_to_delete in user_cards:
                del user_cards[card_to_delete]
                cards[username] = user_cards
                save_card_data(cards)
                flash("❌ Card deleted.")
        else:
            number = request.form['number']
            expiry = request.form['expiry']
            cvv = request.form['cvv']
            name = request.form['name']

            if not number.isdigit() or len(number) != 16:
                flash("❌ Invalid card number.")
                return redirect('/manage_cards')

            user_cards[number] = {
                "expiry": expiry,
                "cvv": cvv,
                "name": name
            }
            cards[username] = user_cards
            save_card_data(cards)
            flash("✅ Card added successfully.")

        return redirect('/manage_cards')

    return render_template('manage_cards.html', cards=user_cards)

@app.route('/record_list', methods=['GET', 'POST'])
def record_list():
    if 'username' not in session or session['role'] != 'Staff':
        return redirect('/login')

    visits = load_patient_visits()
    searched_username = None
    patient_records = []

    if request.method == 'POST':
        searched_username = request.form['patient_username']
        patient_records = visits.get(searched_username, [])

    return render_template('record_list.html',
                           records=patient_records,
                           searched_username=searched_username)

@app.route('/create_charge', methods=['GET', 'POST'])
def create_charge():
    if 'username' not in session or session['role'] != 'Staff':
        return redirect('/login')

    users = load_users()
    charges = load_charges()
    doctor_usernames = [uname for uname, info in users.items() if info.get("role") == "Doctor"]

    if request.method == 'POST':
        username = request.form['username']
        selected_doctor = request.form['doctor']
        try:
            amount = float(request.form['amount'])
        except ValueError:
            flash("❌ Invalid amount.")
            return redirect('/create_charge')

        if username not in users:
            flash("❌ Patient not found.")
            return redirect('/create_charge')

        if username not in charges:
            charges[username] = []

        charges[username].append({
            "doctor": selected_doctor,
            "amount": amount,
            "timestamp": datetime.now().isoformat()
        })

        save_charges(charges)
        flash(f"✅ Charge of ${amount:.2f} added for {username} by {selected_doctor}.")
        return redirect('/create_charge')

    return render_template('create_charge.html', doctors=doctor_usernames)

@app.route('/view_charges', methods=['GET', 'POST'])
def view_charges():
    if 'username' not in session or session['role'] != 'Staff':
        return redirect('/login')

    charges = load_charges()
    copays = load_copay_data()
    selected_username = None
    patient_charges = []
    total_charged = 0
    total_paid = 0
    balance = 0

    if request.method == 'POST':
        selected_username = request.form['username']
        patient_charges = charges.get(selected_username, [])
        total_charged = sum(c['amount'] for c in patient_charges)
        total_paid = sum(p['amount'] for p in copays.get(selected_username, []))
        balance = total_charged - total_paid

    return render_template('view_charges.html',
                           username=selected_username,
                           charges=patient_charges,
                           total_charged=total_charged,
                           total_paid=total_paid,
                           balance=balance)

@app.route('/staff_profile')
def staff_profile():
    if 'username' not in session or session['role'] != 'Staff':
        return redirect('/login')

    users = load_users()
    username = session['username']
    user_info = users.get(username, {})
    return render_template('staff_profile.html', username=username, info=user_info)
@app.route('/edit_employee', methods=['GET', 'POST'])
def edit_employee():
    if 'username' not in session or session['role'] != 'CEO':
        return redirect('/login')

    users = load_users()
    selected_user = None
    editable_roles = ['Staff', 'Nurse', 'Doctor']
    user_info = {}

    if request.method == 'POST':
        selected_user = request.form['username']

        if 'save' in request.form:
            # Save updated data
            if selected_user in users:
                users[selected_user]['salary'] = request.form['salary']
                users[selected_user]['benefits'] = request.form['benefits']
                users[selected_user]['department'] = request.form['department']
                users[selected_user]['employment_type'] = request.form['employment_type']
                save_users(users)
                flash("✅ Employee info updated.")
                return redirect('/edit_employee')

        elif selected_user in users and users[selected_user]['role'] in editable_roles:
            user_info = users[selected_user]

    return render_template('edit_employee.html',
                           users=users,
                           editable_roles=editable_roles,
                           selected_user=selected_user,
                           user_info=user_info)

@app.route('/nurse_profile')
def nurse_profile():
    if 'username' not in session or session['role'] != 'Nurse':
        return redirect('/login')

    users = load_users()
    username = session['username']
    user_info = users.get(username, {})
    return render_template('nurse_profile.html', username=username, info=user_info)
@app.route('/nurse_update', methods=['GET', 'POST'])
def nurse_update():
    if 'username' not in session or session['role'] != 'Nurse':
        return redirect('/login')

    visits = load_patient_visits()
    users = load_users()

    if request.method == 'POST':
        patient_username = request.form['username']

        if patient_username not in users or users[patient_username]['role'] != 'Patient':
            flash("❌ Patient not found.")
            return redirect('/nurse_update')

        if patient_username not in visits or not visits[patient_username]:
            flash("❌ No visits found for this patient.")
            return redirect('/nurse_update')

        latest_visit = visits[patient_username][-1]

        try:
            latest_visit['nurse_entry'] = {
                "weight": float(request.form['weight']),
                "height": float(request.form['height']),
                "blood_pressure": request.form['bp'],
                "pulse": int(request.form['pulse']),
                "reason": request.form['reason'],
                "nurse": session['username'],
                "nurse_timestamp": datetime.now().isoformat()
            }

            with open(PATIENT_VISITS_FILE, 'w') as f:
                f.write(encrypt_data(visits))

            flash("✅ Nurse entry saved successfully.")
            return redirect('/nurse_update')

        except ValueError:
            flash("❌ Invalid data entered.")
            return redirect('/nurse_update')

    return render_template('nurse_update.html')

@app.route('/doctor_review', methods=['GET', 'POST'])
def doctor_review():
    if 'username' not in session or session['role'] != 'Doctor':
        return redirect('/login')

    visits = load_patient_visits()
    users = load_users()
    patient_username = None
    visit_data = None

    if request.method == 'POST':
        patient_username = request.form['username']

        if patient_username not in users or users[patient_username]['role'] != 'Patient':
            flash("❌ Patient not found.")
            return redirect('/doctor_review')

        if patient_username not in visits or not visits[patient_username]:
            flash("❌ No visit found for this patient.")
            return redirect('/doctor_review')

        visit_data = visits[patient_username][-1]

        if 'treatment' in request.form and 'prescription' in request.form:
            visit_data['doctor_entry'] = {
                "treatment": request.form['treatment'],
                "prescription": request.form['prescription'],
                "doctor": session['username'],
                "doctor_timestamp": datetime.now().isoformat()
            }

            with open(PATIENT_VISITS_FILE, 'w') as f:
                f.write(encrypt_data(visits))

            flash("✅ Doctor entry saved successfully.")
            return redirect('/doctor_review')

    return render_template('doctor_review.html', visit=visit_data)

@app.route('/doctor_profile')
def doctor_profile():
    if 'username' not in session or session['role'] != 'Doctor':
        return redirect('/login')

    users = load_users()
    username = session['username']
    user_info = users.get(username, {})
    return render_template('doctor_profile.html', username=username, info=user_info)

def is_last_day_of_month(date):
    next_day = date + timedelta(days=1)
    return next_day.day == 1

def generate_summary_auto(time_filter):
    charges = load_charges()
    doctors_summary = {}
    today = datetime.now().date()
    this_month = today.strftime("%Y-%m")

    for patient_entries in charges.values():
        for charge in patient_entries:
            doctor = charge['doctor']
            timestamp = datetime.fromisoformat(charge['timestamp'])
            date_key = timestamp.date()
            month_key = timestamp.strftime("%Y-%m")

            if (time_filter == 'daily' and date_key != today) or (time_filter == 'monthly' and month_key != this_month):
                continue

            if doctor not in doctors_summary:
                doctors_summary[doctor] = {"patients": 0, "total_charged": 0.0}

            doctors_summary[doctor]["patients"] += 1
            doctors_summary[doctor]["total_charged"] += float(charge['amount'])

    if not doctors_summary:
        return None

    filename = f"{time_filter}_summary_{today.isoformat()}.txt"
    with open(filename, 'w') as f:
        f.write(f"{time_filter.capitalize()} Summary for {today}:\n\n")
        for doc, data in doctors_summary.items():
            f.write(f"- {doc}: {data['patients']} patient(s), ${data['total_charged']:.2f} charged\n")

    return filename

@app.route('/generate_summary/<string:type>')
def generate_summary(type):
    if 'username' not in session or session['role'] != 'CEO':
        return redirect('/login')

    if type not in ['daily', 'monthly']:
        flash("❌ Invalid summary type.")
        return redirect('/dashboard')

    filename = generate_summary_auto(type)
    if filename:
        flash(f"✅ {type.capitalize()} summary generated: {filename}")
    else:
        flash(f"No charges found for {type} summary.")

    return redirect('/dashboard')
@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if 'username' not in session or session['role'] != 'CEO':
        return redirect('/login')

    users = load_users()
    roles = ['Staff', 'Nurse', 'Doctor']

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        role = request.form['role']
        salary = request.form['salary']
        benefits = request.form['benefits']
        department = request.form['department']
        employment_type = request.form['employment_type']

        if username in users:
            flash("❌ Username already exists.")
            return redirect('/manage_users')

        users[username] = {
            "password": hash_password(password),
            "role": role,
            "salary": salary,
            "benefits": benefits,
            "department": department,
            "employment_type": employment_type
        }

        save_users(users)
        flash("✅ New user created.")
        return redirect('/manage_users')

    return render_template('manage_users.html', users=users, roles=roles)

@app.route('/view_login_logs')
def view_login_logs():
    if 'username' not in session or session['role'] != 'CEO':
        return redirect('/login')

    logs = load_login_attempts()
    return render_template('view_login_logs.html', logs=logs)


if __name__ == '__main__':
    app.run(debug=True)
