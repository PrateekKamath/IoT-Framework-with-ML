from flask import Flask, render_template, request, jsonify
import paho.mqtt.client as mqtt
import scapy.all as scapy
import socket
import ipaddress

app = Flask(__name__)

# MQTT setup
mqtt_messages = []  # Store received MQTT messages

def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    client.subscribe("packet_capture_results")  # Subscribe to the desired topic here

def on_message(client, userdata, msg):
    mqtt_messages.append(msg.payload.decode())  # Append received message to the list
    print(msg.topic + " " + str(msg.payload))  # Print received message

mqtt_client = mqtt.Client()
mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message
mqtt_client.connect("test.mosquitto.org", 1883, 60)  # Connect to MQTT broker

class NetworkScanner:

    def __init__(self):
        self.devices = []
        
    def get_local_network(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        
        interface = ipaddress.ip_interface(f"{ip}/24")
        return str(interface.network)

    def scan(self, ip_range):        
        arp = scapy.ARP(pdst=ip_range)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") 
        packet = ether/arp
        
        result = scapy.srp(packet, timeout=3, verbose=0)[0]
        
        for sent, received in result:
            device = {'ip': received.psrc, 'mac': received.hwsrc}
            self.devices.append(device)

    def print_devices(self):
        print(f"Total devices detected: {len(self.devices)}")
        print("Devices found:")
        for device in self.devices:
            print(f"IP {device['ip']}, MAC {device['mac']}")

@app.route('/')
def index():
    scanner = NetworkScanner()
    scanner.scan(scanner.get_local_network())  # Trigger the network scan
    connected_devices_count = len(scanner.devices)  # Get the number of connected devices

    return render_template('index.html', devices=connected_devices_count)

@app.route('/perform_attack', methods=['POST'])
def perform_attack():
    attack_type = request.form.get('attack_type')
    # Perform the selected attack based on 'attack_type'
    # (Your logic to perform the attack goes here)

    # Publish the result on the MQTT topic
    result = "Detection Begun for:" + attack_type + " attack"  # Replace this with the actual result
    mqtt_client.publish("packet_capture_results", result)  # Publish the result

    return jsonify({'success': True})

@app.route('/get_messages', methods=['GET'])
def get_messages():
    return jsonify({'messages': mqtt_messages})  # Return the MQTT messages as JSON

if __name__ == '__main__':
    mqtt_client.loop_start()
    app.run(host='0.0.0.0', port=5000, debug=True)