import BAC0
import RPi.GPIO as GPIO
import time
import Adafruit_DHT   
import base64
import paho.mqtt.client as mqtt

from Cryptodome.Cipher import AES  # from pycryptodomex v-y.10.4
from BAC0.core.devices.local.models import analog_input

bacnet = BAC0.lite(ip = '192.168.1.4/24')
print("Find device ......")

IV_LENGTH = 32

def pad(s): 
    s=str(s) 
    return s + (IV_LENGTH - len(s) %
                        IV_LENGTH) * chr(IV_LENGTH - len(s) % IV_LENGTH)


def unpad(s): return s[0:-ord(s[-1:])]
# Konfigurasi pin GPIO yang digunakan
pin = 20
sensor = Adafruit_DHT.DHT11

# coding untuk mqtt
broker_address = "test.mosquitto.org"
port = 1883

def readsensor():
    humidity, temperature = Adafruit_DHT.read_retry(sensor, pin)
    return {
        '/humidity/TA': humidity,
        '/temperature/TA':temperature,
    }
humisubs = "/humidity/TA"
tempsubs = "/temperature/TA"

def readsensorbacnet():
    kelembaban, suhu = Adafruit_DHT.read_retry(sensor, pin)

def on_connect(client, userdata, flags, rc):
    print("Connected - rc:", rc)

total_encryption_time = 0
iterations = 0
while True: 
    print ("Connection from: ",bacnet)

    while True:
        sensor_data = readsensor()
        start_time = time.time()
        for topic, value in sensor_data.items():
            secret_key = bytes("mysecretpassword", encoding='utf-8')
            iv = bytes("mysecretpassword", encoding='utf-8')
            cipher = AES.new(secret_key, AES.MODE_CBC, iv)
            payload = int(value)
            print(f"\n ni payload {payload}")
            chathumi = pad(payload)
            chattemp = pad(payload)
            print(f"ni chathumi {chathumi}\n")
            cipher_byteshumi = base64.b64encode(iv + cipher.encrypt(chathumi.encode("utf8")))
            cipher_bytestemp = base64.b64encode(iv + cipher.encrypt(chattemp.encode("utf8")))
            print(f"ni cipher humi abis encode {cipher_byteshumi}")
            
            end_time = time.time()

            encryption_time = end_time - start_time
            total_encryption_time += encryption_time
            iterations += 1

            print(f"Waktu enkripsi : {encryption_time}detik")

            if topic == '/humidity/TA':
                time.sleep(1)
            elif topic == '/temperature/TA':
                time.sleep(1)

            client = mqtt.Client()
            client.on_connect = on_connect
            client.connect(broker_address, port)
            client.publish(topic, cipher_byteshumi)
            client.disconnect()
        time.sleep(3)
        humidity, temperature = Adafruit_DHT.read_retry(sensor, pin)
        if humidity is not None and temperature is not None:
            sensor_data_raspy="{0:0.1f}*C,{1:0.1f}%".format(temperature, humidity)
            print('Suhu={0:0.1f}*C  Kelembaban={1:0.1f}%'.format(temperature, humidity))
            

        else:
            sensor_data_raspy="Gagal membaca data dari sensor DHT11"
            print('Gagal membaca data dari sensor DHT11.')
        time.sleep(1)

        try:
        
            _new_object = analog_input(
                instance=1,
                name="Current_Temperature",
                description="Current Temperature in degC ",
                presentValue= temperature,
                properties={"units": "degreesCelsius"},
                )

            _new_object = analog_input(
                instance=2,
                name="Current_Humidity",
                description="Current Humidity in % ",
                presentValue= humidity,
                properties={"units": "percent"},
                )

            _new_object.add_objects_to_application(bacnet)

            bacnet.this_device.objectIdentifier
        except Exception as e:
            print(f"ex {e}")
        def destroy():
            GPIO.cleanup()