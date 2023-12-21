import pyshark
import time
import csv
import pandas as pd
import datetime
import signal
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from joblib import dump, load
import time
import numpy as np
import sys
import scapy.all as scapy
import socket
import ipaddress

class SYN_DoS_DDoS:
    def __init__(self, iface_name='Wi-Fi', allowed_IP=None, capture_limit=1000):
        self.iface_name = iface_name
        self.allowed_IP = allowed_IP if allowed_IP else ['192.168.199.129', '192.168.199.1', '192.168.13.239', '10.20.204.95', '192.168.1.3', '192.168.242.239']
        self.capture_limit = capture_limit
        self.previous_time = 0
        self.data_to_write = []
        self.packet_count = 0
        self.start_time = 0
        self.syn_flag_counts = {}
        self.source_ip_counts = {}
        self.devices = []

    def get_ip_layer_name(self, packet):
        if 'IP' in packet:
            return 4
        elif 'IPv6' in packet:
            return 6
        return None

    def save_data(self, filename='test.csv'):
        with open(filename, 'a', newline='') as csvfile:
            filewriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            for row in self.data_to_write:
                filewriter.writerow(row)

    def handle_interrupt(self, signal, frame):
        print("Capturing interrupted. Saving data...")
        self.save_data()
        print("Packets Collected:", self.packet_count)
        end_time = time.time()
        duration = end_time - self.start_time
        print("Duration (seconds):", duration)

        current_time = datetime.datetime.now()
        formatted_time = current_time.strftime("%H:%M:%S %d-%m-%Y %A")
        print("Time and Date:", formatted_time)

        self.prediction()
        sys.exit(0)

    def capture_packets(self):
        self.start_time = time.time()
        self.packet_count = 0
        self.data_to_write = []

        cap = pyshark.LiveCapture(interface=self.iface_name)

        try:
            with open('test.csv', 'w', newline='') as csvfile:
                filewriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                filewriter.writerow(['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port',
                                     'Packet Length', 'SYN', 'ACK', 'FIN', 'RST', 'Packets/Time', 'Time Between Packets', 'target'])

                for pkt in cap:
                    self.packet_count += 1
                    transport_layer = None
                    try:
                        if pkt.highest_layer != 'ARP':
                            ip = None
                            ip_layer = self.get_ip_layer_name(pkt)
                            if ip_layer == 4:
                                ip = pkt.ip
                                ipv = 0
                                if pkt.transport_layer is None:
                                    transport_layer = 'None'
                                else:
                                    transport_layer = pkt.transport_layer
                            elif ip_layer == 6:
                                ip = pkt.ipv6
                                ipv = 1

                            source_ip = ip.src
                            target_ip = ip.dst

                            if source_ip not in self.allowed_IP:
                                target = source_ip
                            else:
                                target = 'Normal'

                            syn_flag = 0
                            ack_flag = 0
                            fin_flag = 0
                            rst_flag = 0

                            if 'TCP' in pkt:
                                if pkt.tcp.flags_syn == '1':
                                    syn_flag = 1
                                if pkt.tcp.flags_ack == '1':
                                    ack_flag = 1
                                if pkt.tcp.flags_fin == '1':
                                    fin_flag = 1
                                if pkt.tcp.flags_reset == '1':
                                    rst_flag = 1

                                if syn_flag == 1:
                                    self.syn_flag_counts[syn_flag] = self.syn_flag_counts.get(syn_flag, 0) + 1
                                self.source_ip_counts[source_ip] = self.source_ip_counts.get(source_ip, 0) + 1

                            current_time = time.time()
                            time_between_packets = current_time - self.previous_time
                            packets_per_second = self.packet_count / (current_time - self.start_time)
                            packets_per_second_formatted = f'{packets_per_second:.3f}'
                            self.previous_time = current_time

                            time_between_packets_ns = f'{time_between_packets:.3f}'

                            self.data_to_write.append([pkt.highest_layer, transport_layer, source_ip, target_ip,
                                                       pkt[pkt.transport_layer].srcport,
                                                       pkt[pkt.transport_layer].dstport,
                                                       pkt.length, syn_flag, ack_flag, fin_flag, rst_flag,
                                                       packets_per_second_formatted, time_between_packets_ns, target])

                            if self.packet_count >= self.capture_limit:
                                break

                        else:
                            transport_layer = 'ARP'
                            if pkt.arp.src_proto_ipv4 not in self.allowed_IP:
                                target = pkt.arp.src_proto_ipv4
                            else:
                                target = 'Normal'

                    except (UnboundLocalError, AttributeError) as e:
                        pass

                    if self.packet_count >= self.capture_limit:
                        break

        except OSError as e:
            print("Tshark lost connection with the network interface. Exiting...")
            sys.exit(1)

        self.save_data()
        self.prediction()
        
    def train_capture_packets(self):
        try:
            total_packets = 10000  # Total packets to capture
            packets_captured = 0
            start_time = time.time()
            # Function to determine the IP layer (IPv4 or IPv6)
            def get_ip_layer_name(packet):
                if 'IP' in packet:
                    return 4
                elif 'IPv6' in packet:
                    return 6
                return None

            allowed_IP = ['192.168.199.129', '192.168.199.1', '192.168.13.239', '10.20.204.95']
            previous_time = 0

            # Loop for capturing benign and attack traffic
            for traffic_type in ['Benign', 'Attack']:
                print(f"Capturing {traffic_type.lower()} traffic...")
                packet_count = 0  # Initialize packet count for this traffic type

                with open(f'{traffic_type}_Traffic.csv', 'w', newline='') as csvfile:
                    filewriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                    filewriter.writerow(
                        ['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port',
                         'Packet Length', 'SYN', 'ACK', 'FIN', 'RST', 'Packets/Time', 'Time Between Packets', 'target'])

                    cap = pyshark.LiveCapture(interface=self.iface_name)

                    for pkt in cap:
                        packet_count += 1  # Increment packet count
                        transport_layer = None  # Initialize transport_layer outside the try block
                        try:
                            if packet_count > total_packets:
                                break  # Stop capturing packets after 10000 packets

                            ip_layer = get_ip_layer_name(pkt)
                            if ip_layer == 4:
                                ip = pkt.ip
                                ipv = 0  # target test
                                if pkt.transport_layer is None:
                                    transport_layer = 'None'
                                else:
                                    transport_layer = pkt.transport_layer
                            elif ip_layer == 6:
                                ip = pkt.ipv6
                                ipv = 1  # target test

                            source_ip = ip.src
                            target_ip = ip.dst

                            if source_ip not in allowed_IP:
                                target = source_ip
                            else:
                                target = 'Normal'

                            syn_flag = 0
                            ack_flag = 0
                            fin_flag = 0
                            rst_flag = 0

                            if 'TCP' in pkt:
                                if pkt.tcp.flags_syn == '1':
                                    syn_flag = 1
                                if pkt.tcp.flags_ack == '1':
                                    ack_flag = 1
                                if pkt.tcp.flags_fin == '1':
                                    fin_flag = 1
                                if pkt.tcp.flags_reset == '1':
                                    rst_flag = 1

                            current_time = time.time()
                            time_between_packets = current_time - previous_time
                            packets_per_second = packet_count / (current_time - start_time)
                            packets_per_second_formatted = f'{packets_per_second:.3f}'
                            previous_time = current_time

                            time_between_packets_ns = f'{time_between_packets:.3f}'

                            packet_data = [pkt.highest_layer, transport_layer, source_ip, target_ip,
                                           pkt[pkt.transport_layer].srcport,
                                           pkt[pkt.transport_layer].dstport,
                                           pkt.length, syn_flag, ack_flag, fin_flag, rst_flag,
                                           packets_per_second_formatted, time_between_packets_ns, target]

                            filewriter.writerow(packet_data)

                            if packet_count >= total_packets:
                                break  # Stop capturing packets if the required count is reached

                        except (UnboundLocalError, AttributeError) as e:
                            pass

                print(f"{traffic_type.lower()} traffic captured and stored in {traffic_type}_Traffic.csv.")

                # Delay between capturing benign and attack traffic
                if traffic_type == 'Benign':
                    print("Delay for 5 seconds before capturing attack traffic...")
                    time.sleep(5)

        except KeyboardInterrupt:
            print("\nKeyboard interrupt detected. Stopping the training capture.")
            sys.exit(0)


    def train_kNN(self):
        # Combine SYN_DoS.csv and Benign_Traffic.csv into Combined_Traffic.csv
        benign_traffic_data = pd.read_csv('Benign_Traffic.csv')
        benign_traffic_data['target'] = 'Normal'

        attack_traffic_data = pd.read_csv('Attack_Traffic.csv')
        attack_traffic_data['target'] = 'Attack'
        combined_traffic_data = pd.concat([attack_traffic_data, benign_traffic_data]).sample(frac=1).reset_index(drop=True)
        combined_traffic_data.to_csv('Combined_Traffic.csv', index=False)

        # Load the Combined_Traffic.csv dataset
        data = pd.read_csv('Combined_Traffic.csv', delimiter=',')

        # Drop columns 'Highest Layer', 'Source IP', and 'Dest IP'
        data = data.drop(['Highest Layer', 'Source IP', 'Dest IP'], axis=1)

        # Label encode non-integer and non-float columns
        label_encoder = LabelEncoder()
        non_numeric_columns = data.select_dtypes(exclude=['int', 'float']).columns
        for column in non_numeric_columns:
            data[column] = label_encoder.fit_transform(data[column])

        X = data.drop('target', axis=1)  # Features
        y = data['target']  # Target variable

        X_train, X_test, y_train, y_test = train_test_split(X, y)

        # Feature Scaling
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test = scaler.transform(X_test)

        # Hyperparameter tuning with Stratified Cross-Validation
        best_k = 0
        best_score = 0

        stratified_kf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        for k in range(1, 21):
            knn = KNeighborsClassifier(n_neighbors=k, weights='distance')
            scores = cross_val_score(knn, X_train, y_train, cv=stratified_kf)

            if scores.mean() > best_score:
                best_score = scores.mean()
                best_k = k

        print("Best k:", best_k)

        # Train the model with the best k
        knn = KNeighborsClassifier(n_neighbors=best_k, weights='distance')
        knn.fit(X_train, y_train)

        predictions = knn.predict(X_test)

        print()
        print("Number of Neighbors: ", knn.n_neighbors)
        print()
        print("Confusion Matrix: ", "\n", confusion_matrix(y_test, predictions))
        print()
        print("Classification Report: ", "\n", classification_report(y_test, predictions))
        print()

        # Save the k-NN model
        dump(knn, 'kNN_.sav')
    
    def test_kNN(self):
        
        knn_model = load('kNN_.sav')

        syn_dos_data = pd.read_csv('Attack_Traffic.csv')

        syn_dos_data = syn_dos_data.drop(['Highest Layer', 'Source IP', 'Dest IP'], axis=1)

        label_encoder = LabelEncoder()
        non_numeric_columns = syn_dos_data.select_dtypes(exclude=['int', 'float']).columns
        for column in non_numeric_columns:
            syn_dos_data[column] = label_encoder.fit_transform(syn_dos_data[column])

        X_syn_dos = syn_dos_data.drop('target', axis=1)
        y_syn_dos = syn_dos_data['target']

        scaler = StandardScaler()
        X_syn_dos = scaler.fit_transform(X_syn_dos)

        predictions = knn_model.predict(X_syn_dos)
        print(predictions)

        np.set_printoptions(threshold=np.inf)
        count_0 = (predictions == 0).sum()
        count_1 = (predictions == 1).sum()

        print("Number of occurrences of 0:", count_0)
        print("Number of occurrences of 1:", count_1)
        if count_1 > count_0:
            print("ATTACK DETECTED !!")
        else:
            print("Normal Traffic")

    def prediction(self):
        knn_model = load('kNN.sav')
        syn_dos_data = pd.read_csv('test.csv')
        syn_dos_data = syn_dos_data.drop(['Highest Layer', 'Source IP', 'Dest IP'], axis=1)
        label_encoder = LabelEncoder()
        non_numeric_columns = syn_dos_data.select_dtypes(exclude=['int', 'float']).columns
        for column in non_numeric_columns:
            syn_dos_data[column] = label_encoder.fit_transform(syn_dos_data[column])

        X_syn_dos = syn_dos_data.drop('target', axis=1)
        y_syn_dos = syn_dos_data['target']

        scaler = StandardScaler()
        X_syn_dos = scaler.fit_transform(X_syn_dos)
        predictions = knn_model.predict(X_syn_dos)

        np.set_printoptions(threshold=np.inf)
        count_1 = (predictions == 1).sum()
        count_2 = (predictions == 2).sum()

        current_time = datetime.datetime.now()
        formatted_time = current_time.strftime("%H:%M:%S %d-%m-%Y %A")

        majority_syn_flag = max(self.syn_flag_counts, key=self.syn_flag_counts.get)
        majority_ip = max(self.source_ip_counts, key=self.source_ip_counts.get)

        if count_2 > count_1 and self.syn_flag_counts.get(majority_syn_flag, 0) > len(predictions) / 2 and self.source_ip_counts.get(majority_ip, 0) > len(predictions) / 2:
            print(f"SYN DoS attack detected from IP Address: {majority_ip} at {formatted_time}")
        elif self.syn_flag_counts.get(1, 0) > len(predictions) / 2 and len(self.source_ip_counts) > 1:
            print(f"SYN DDoS Attack Detected from multiple addresses at {formatted_time}")
        else:
            print("Normal Traffic:", formatted_time)

    def publish_connected_devices(self):
        connected_devices_topic = 'connected_devices'
        for device in self.devices:
            device_info = f"IP: {device['ip']}, MAC: {device['mac']}"
            self.mqtt_client.publish(connected_devices_topic, device_info)

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
        connected_devices_topic = 'connected_devices'
        for device in self.devices:
            device_info = f"IP: {device['ip']}, MAC: {device['mac']}"
            self.publish_to_mqtt(device_info, connected_devices_topic)


# Initialize PacketCapture instance and handle KeyboardInterrupt
packet_capture_instance = SYN_DoS_DDoS(iface_name='Wi-Fi')
signal.signal(signal.SIGINT, packet_capture_instance.handle_interrupt)

try:
    # Scan for devices in the network
    local_network = packet_capture_instance.get_local_network()
    packet_capture_instance.scan(local_network)
    
    # Print the detected devices
    packet_capture_instance.print_devices()
    
    # Capture and process packets
    while True:
        packet_capture_instance.capture_packets()
        
except KeyboardInterrupt:
    print("\nKeyboard interrupt detected. Stopping the packet capture.")




