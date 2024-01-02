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

app = Flask(_name_)
# app.config['SECRET'] = ''
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['MQTT_BROKER_URL'] = 'test.mosquitto.org'
app.config['MQTT_BROKER_PORT'] = 1883
app.config['MQTT_USERNAME'] = ''
app.config['MQTT_PASSWORD'] = '  '
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
    secret_key = bytes("mysecretpassword", encoding='utf-8')

    topic = message.topic
    payload = message.payload
    print(f"payload {payload}")
    decoded = base64.b64decode(message.payload)
    print(f"decode messsage {message}")
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
    if request.m…
