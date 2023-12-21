import pyshark
import time
import csv
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import sys
import signal
from sklearn.preprocessing import StandardScaler
from joblib import load
import numpy as np
import datetime

allowed_IP = ['192.168.199.129', '192.168.199.1', '192.168.13.239', '10.20.204.95', '192.168.1.3', '192.168.242.239']
previous_time = 0
capture_limit = 250
iface_name = 'Wi-Fi'

def get_ip_layer_name(packet):
    if 'IP' in packet:
        return 4
    elif 'IPv6' in packet:
        return 6
    return None

# Global variables for tracking majority SYN flag and IPs
syn_flag_counts = {}
source_ip_counts = {}

def save_data(data_to_write):
    with open('test.csv', 'a', newline='') as csvfile:
        filewriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        for row in data_to_write:
            filewriter.writerow(row)

def prediction():
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

    # Check majority SYN flag and source IPs
    majority_syn_flag = max(syn_flag_counts, key=syn_flag_counts.get)
    majority_ip = max(source_ip_counts, key=source_ip_counts.get)

    if count_2 > count_1 and syn_flag_counts.get(majority_syn_flag, 0) > len(predictions) / 2 and source_ip_counts.get(majority_ip, 0) > len(predictions) / 2:
        print(f"SYN DoS attack detected from IP Address: {majority_ip} at {formatted_time}")
    elif syn_flag_counts.get(1, 0) > len(predictions) / 2 and len(source_ip_counts) > 1:
        print(f"SYN DDoS Attack Detected from multiple addresses at {formatted_time}")
    else:
        print("Normal Traffic:", formatted_time)

def handle_interrupt(signal, frame):
    print("Capturing interrupted. Saving data...")
    save_data(data_to_write)
    print("Packets Collected:", packet_count)
    end_time = time.time()
    duration = end_time - start_time
    print("Duration (seconds):", duration)

    current_time = datetime.datetime.now()
    formatted_time = current_time.strftime("%H:%M:%S %d-%m-%Y %A")
    print("Time and Date:", formatted_time)

    prediction()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_interrupt)

while True:
    start_time = time.time()
    packet_count = 0
    data_to_write = []

    cap = pyshark.LiveCapture(interface=iface_name)
    
    try:
        with open('test.csv', 'w', newline='') as csvfile:
            filewriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            filewriter.writerow(
                ['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port',
                'Packet Length', 'SYN', 'ACK', 'FIN', 'RST', 'Packets/Time', 'Time Between Packets', 'target'])

            for pkt in cap:
                packet_count += 1
                transport_layer = None
                try:
                    if pkt.highest_layer != 'ARP':
                        ip = None
                        ip_layer = get_ip_layer_name(pkt)
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

                            # Update counts for SYN flag and source IPs
                            if syn_flag == 1:
                                syn_flag_counts[syn_flag] = syn_flag_counts.get(syn_flag, 0) + 1
                            source_ip_counts[source_ip] = source_ip_counts.get(source_ip, 0) + 1

                        current_time = time.time()
                        time_between_packets = current_time - previous_time
                        packets_per_second = packet_count / (current_time - start_time)
                        packets_per_second_formatted = f'{packets_per_second:.3f}'
                        previous_time = current_time

                        time_between_packets_ns = f'{time_between_packets:.3f}'

                        data_to_write.append([pkt.highest_layer, transport_layer, source_ip, target_ip,
                                            pkt[pkt.transport_layer].srcport,
                                            pkt[pkt.transport_layer].dstport,
                                            pkt.length, syn_flag, ack_flag, fin_flag, rst_flag,
                                            packets_per_second_formatted, time_between_packets_ns, target])

                        if packet_count >= capture_limit:
                            break

                    else:
                        transport_layer = 'ARP'
                        if pkt.arp.src_proto_ipv4 not in allowed_IP:
                            target = pkt.arp.src_proto_ipv4
                        else:
                            target = 'Normal'

                except (UnboundLocalError, AttributeError) as e:
                    pass

                if packet_count >= capture_limit:
                    break

    except OSError as e:
        print("Tshark lost connection with the network interface. Exiting...")
        sys.exit(1)

    save_data(data_to_write)
    prediction()
