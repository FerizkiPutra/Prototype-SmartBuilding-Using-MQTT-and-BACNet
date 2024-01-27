from flask import Flask, render_template, jsonify, redirect, request, flash, url_for
import json
import database
import base64
from random import choice
from datetime import datetime
import person
import os
import binascii
import eventlet
import json
from passlib.hash import md5_crypt as sha
from flask_mqtt import Mqtt
from flask_socketio import SocketIO
from Cryptodome.Cipher import AES  # from pycryptodomex v-3.10.4
from Cryptodome.Random import get_random_bytes

IV_LENGTH = 16


def pad(s): return s + (IV_LENGTH - len(s) %
                        IV_LENGTH) * chr(IV_LENGTH - len(s) % IV_LENGTH)


def unpad(s): return s[0:-ord(s[-1:])]


eventlet.monkey_patch()

app = Flask(__name__)
# app.config['SECRET'] = ''
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['MQTT_BROKER_URL'] = 'test.mosquitto.org'
app.config['MQTT_BROKER_PORT'] = 1883
app.config['MQTT_USERNAME'] = ''
app.config['MQTT_PASSWORD'] = ''
app.config['MQTT_REFRESH_TIME'] = 1.0
app.config['MQTT_TLS_ENABLED'] = False
logged_in = {}
api_loggers = {}
mydb = database.db('root', '127.0.0.1', '', 'arms')
# test api key aGFja2luZ2lzYWNyaW1lYXNmc2FmZnNhZnNhZmZzYQ==
mqtt = Mqtt(app)
socketio = SocketIO(app)
secret_key = bytes("mysecretpassword", encoding='utf-8')
msg = {}


@mqtt.on_connect()
def handle_connect(client, userdata, flags, rc):
    mqtt.subscribe('/humidity/TA')
    mqtt.subscribe('/temperature/TA')
    # mqtt.subscribe('/light/TA')


@mqtt.on_message()
def handle_mqtt_message(client, userdata, message):
    topic = message.topic
    payload = message.payload
    # decoded = base64.b64decode(message.payload)
    # iv = decoded[:AES.block_size]
    # cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    # original_bytes = unpad(cipher.decrypt(decoded[16:]))
    # msg = original_bytes.decode()

    # if topic == 'humi':
    #     device = 'ARMS12012'
    #     query = 'update node set humidity={} where deviceID="{}";'.format(
    #         msg, device)
    #     mydb.cursor.execute(query)
    #     mydb.db.commit()
    #     print(msg)
    # elif topic == 'temp':
    #     device = 'ARMS12012'
    #     query = 'update node set temp={} where deviceID="{}";'.format(
    #         msg, device)
    #     mydb.cursor.execute(query)
    #     mydb.db.commit()
    #     print(msg)
    # elif topic == 'light':
    #     device = 'ARMS12012'
    #     query = 'update node set light={} where deviceID="{}";'.format(
    #         msg, device)
    #     mydb.cursor.execute(query)
    #     mydb.db.commit()
    #     print(msg)
    # else:
    #     print('error')
    # secret_key = b"mysecretpassword"

    if topic == '/humidity/TA' or topic == '/temperature/TA' or topic == '/light/TA':
        if topic == '/humidity/TA':
            code = 'humidity'
        elif topic == '/temperature/TA':
            code = 'temperature'
        elif topic == '/light/TA':
            code = 'light'

        decoded = base64.b64decode(payload)
        iv = decoded[:IV_LENGTH]
        print(decode)
        encrypted_payload = decoded[IV_LENGTH:]
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
        decrypted_payload = unpad(cipher.decrypt(encrypted_payload))
        msg = decrypted_payload.decode()
        print(f"Received message from {topic}: {msg}")
        # print(msg)
        # print(decode)
        device = 'ARMS12012'

        if msg != '':
            query = 'UPDATE node SET {} = %s WHERE deviceID = %s'.format(code)
            mydb.cursor.execute(query, (msg, device))
            mydb.db.commit()
        else:
            print("Empty message. Skipping database update.")


@app.route("/login", methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        user = person.user(request.form['username'], request.form['password'])
        if user.authenticated:
            user.session_id = str(binascii.b2a_hex(os.urandom(15)))
            logged_in[user.username] = {"object": user}
            return redirect('/overview/{}/{}'.format(request.form['username'], user.session_id))
        else:
            error = "invalid Username or Password"

    return render_template('login.html', error=error)


@app.route("/settings/<string:username>/<string:session>", methods=['GET', 'POST'])
def settings(username, session):

    global logged_in
    if username in logged_in and (logged_in[username]['object'].session_id == session):
        user = {
            "username": username,
            "nama": logged_in[username]["object"].first + " " + logged_in[username]["object"].last,
            "image": "/static/images/amanSingh.jpg",
            "api": logged_in[username]["object"].api,
            "session": session,
            "deviceid": logged_in[username]["object"].deviceid
        }
    return render_template('settings.html', submenu='settings', user=user)


@app.route("/register", methods=['GET', 'POST'])
def register():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        first = request.form['first']
        last = request.form['last']
        email = request.form['email']
        phone_number = request.form['phone']
        deviceid = 'ARMS12012'
        encrypt = sha.encrypt(password)
        if not (username or password or first or last or email or phone_number):
            error = "please, fill all fields!"
        else:
            query = "insert into users (username, password, first_name, last_name, email, phone_number, last_login, deviceid) values ('{0}', '{1}', '{2}', '{3}', '{4}', '{5}', now(), '{6}');".format(
                username, encrypt, first, last, email, phone_number, deviceid)
            # print(query)
            mydb.cursor.execute(query)
            mydb.db.commit()
            flash("Register Sukses!")
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template('home.html', title='HOME - Landing Page')


@app.route('/overview/<string:username>/<string:session>', methods=['GET', 'POST'])
def overview(username, session):

    global logged_in
    if username in logged_in and (logged_in[username]['object'].session_id == session):
        user = {
            "username": username,
            "nama": logged_in[username]["object"].first + " " + logged_in[username]["object"].last,
            "image": "/static/images/amanSingh.jpg",
            "session": session,
            "deviceid": logged_in[username]["object"].deviceid
        }
        return render_template('overview.html', title='Overview - Dashboard', user=user, submenu='overview')

    else:
        return redirect('/login')

# this location will get to the api setting


@app.route('/apisettings/<string:username>/<string:session>', methods=['GET', 'POST'])
def apisettings(username, session):

    global logged_in

    if username in logged_in and (logged_in[username]['object'].session_id == session):
        user = {
            "username": username,
            "image": "/static/images/amanSingh.jpg",
            "api": logged_in[username]["object"].api,
            "session": session
        }

        devices = [
            {"Dashboard": "device1",
             "deviceID": "Device1"
             }
        ]
        return render_template('api_settings.htm', title='API-Settings', user=user, devices=devices)

    else:
        return redirect('/login')


# this part is for the profile view
@app.route('/profile/<string:username>/<string:session>', methods=['GET', 'POST'])
def profile(username, session):

    global logged_in

    if username in logged_in and (logged_in[username]['object'].session_id == session):
        user = {
            "username": username,
            "image": "/static/images/amanSingh.jpg",
            "api": logged_in[username]["object"].api,
            "session": session,
            "firstname": logged_in[username]["object"].first,
            "lastname": logged_in[username]["object"].last,
            "email": logged_in[username]["object"].email,
            "phone": logged_in[username]["object"].phone,
            "lastlogin": logged_in[username]["object"].last_login,
        }

        devices = [
            {"Dashboard": "device1",
             "deviceID": "ARMS12012"
             }
        ]
        return render_template('profile.htm', title='API-Settings', user=user, devices=devices)

    else:
        return redirect('/login')


@app.route('/logout/<string:username>/<string:session>', methods=['GET', 'POST'])
def logout(username, session):

    global logged_in

    if username in logged_in and (logged_in[username]['object'].session_id == session):
        logged_in.pop(username)
        # print("logged out")
        return redirect('/')
    else:
        return redirect('/login')


# this is the testing for api
@app.route("/api/<string:apikey>/test", methods=["GET", "POST"])
def apitest(apikey):
    return {"data": "working Fine Connected to the api server"}


# get all the devices information from the user
@app.route("/api/<string:apikey>/listdevices", methods=['GET', 'POST'])
def listdevices(apikey):
    global api_loggers
    global mydb
    if not (apikey in api_loggers):
        try:
            query = "select username from users where api_key = '{}'".format(
                apikey)
            mydb.cursor.execute(query)
            username = mydb.cursor.fetchall()
            username = username[0][0]
            apiuser = person.user(username, "dummy")
            apiuser.authenticated = True
            devices_list = apiuser.get_devices()
            api_loggers[apikey] = {"object": apiuser}
            return jsonify(devices_list)
        except Exception as e:
            print(e)
            return jsonify({"data": "Oops Looks like api is not correct"})

    else:
        data = api_loggers[apikey]["object"].get_devices()
        return jsonify(data)


randlist = [i for i in range(0, 100)]


@app.route('/user/<string:username>/deviceinfo/<string:deviceID>', methods=['GET', 'POST'])
def device_info(username, deviceID):

    global mydb
    if deviceID != '':
        try:
            apiuser = person.user(username, "")
            apiuser.authenticated = True
            data = apiuser.dev_info(deviceID)
            # this part is hard coded so remove after fixing the issue
            data = list(data)
            return jsonify(data)
        except Exception as e:
            print(e)
            return jsonify({"data": "data tidak ditemukan"})

    else:
        # this part is hard coded so remove after fixing the issue
        return jsonify({"data": "device id kosong"})


@app.route('/api/<string:apikey>/fieldstat/<string:fieldname>', methods=['GET', 'POST'])
def fieldstat(apikey, fieldname):

    global api_loggers
    global mydb
    if not (apikey in api_loggers):
        try:
            query = "select username from users where api_key = '{}'".format(
                apikey)
            mydb.cursor.execute(query)
            username = mydb.cursor.fetchall()
            username = username[0][0]
            apiuser = person.user(username, "dummy")
            apiuser.authenticated = True
            data = apiuser.field_values(fieldname)
            api_loggers[apikey] = {"object": apiuser}
            return jsonify(data)
        except Exception as e:
            print(e)
            return jsonify({"data": "Oops Looks like api is not correct"})

    else:
        data = api_loggers[apikey]["object"].field_values(fieldname)
        return jsonify(data)


@app.route('/api/<string:apikey>/devicestat/<string:fieldname>/<string:deviceID>', methods=['GET', 'POST'])
def devicestat(apikey, fieldname, deviceID):

    global api_loggers
    global mydb
    if not (apikey in api_loggers):
        try:
            query = "select username from users where api_key = '{}'".format(
                apikey)
            mydb.cursor.execute(query)
            username = mydb.cursor.fetchall()
            username = username[0][0]
            apiuser = person.user(username, "dummy")
            apiuser.authenticated = True
            data = apiuser.device_values(fieldname, deviceID)
            api_loggers[apikey] = {"object": apiuser}
            return jsonify(data)
        except Exception as e:
            print(e)
            return jsonify({"data": "Oops Looks like api is not correct"})

    else:
        data = api_loggers[apikey]["object"].device_values(fieldname, deviceID)
        return jsonify(data)


@app.route('/api/<string:apikey>/update/<string:data>', methods=['GET', 'POST'])
def update_values(apikey, data):
    global mydb
    try:
        data = decode(data)
        output = mydb.get_apikeys()
        if apikey in output:
            if (len(data) == 6) and (type(data) is list):
                fieldname = data[0]
                deviceID = data[1]
                temp = data[2]
                humidity = data[3]
                moisture = data[4]
                light = data[5]
                mydb.update_values(apikey, fieldname, deviceID,
                                   temp, humidity, moisture, light)
                return ("Values Updated")
            else:
                return "Data Decoding Error!"
        else:
            return "Api key invalid"

    except Exception as e:
        print(e)
        return jsonify({"data": "Oops Looks like api is not correct"})


@app.route("/api/<string:apikey>/temperature", methods=["GET", "POST"])
def get_temperature(apikey):

    randData = choice(randlist)
    time = datetime.now()
    time = time.strftime("%H:%M:%S")
    response = [time, randData]
    return jsonify(response)


@app.route("/api/<string:apikey>/moisture", methods=["GET", "POST"])
def get_moisture(apikey):

    randData = choice(randlist)
    time = datetime.now()
    time = time.strftime("%H:%M:%S")
    response = [time, randData]
    return jsonify(response)


@app.route("/api/<string:apikey>/humidity", methods=["GET", "POST"])
def get_humidity(apikey):

    randData = choice(randlist)
    time = datetime.now()
    time = time.strftime("%H:%M:%S")
    response = [time, randData]
    return jsonify(response)


@app.route("/api/<string:apikey>/light", methods=["GET", "POST"])
def get_light(apikey):

    randData = choice(randlist)
    time = datetime.now()
    time = time.strftime("%H:%M:%S")
    response = [time, randData]
    return jsonify(response)


def encode(data):
    data = json.dumps(data)
    message_bytes = data.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message


def decode(base64_message):
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')
    return json.loads(message)


if __name__ == "__main__":
    mqtt.init_app(app)
    app.run(host="localhost", port="8000", debug=True)
