import pyshark
import time
import csv
import datetime
import sys

class PacketCapture:
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

    def save_data(self, filename='test.csv'):
        with open(filename, 'a', newline='') as csvfile:
            filewriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            for row in self.data_to_write:
                filewriter.writerow(row)

    def get_ip_layer_name(self, packet):
        if 'IP' in packet:
            return 4
        elif 'IPv6' in packet:
            return 6
        return None

    def capture_packets(self):
        # Collect user input for fields to capture
        ''''Highest Layer': Indicates the highest-level protocol of the captured packet (e.g., TCP, UDP, HTTP).
        'Transport Layer': Indicates the specific transport layer protocol (e.g., TCP, UDP).
        'Source IP': Represents the source IP address of the packet.
        'Dest IP': Represents the destination IP address of the packet.
        'Source Port': Indicates the source port number of the packet.
        'Dest Port': Indicates the destination port number of the packet.
        'Packet Length': Represents the length of the captured packet.
        'SYN': Flag indicating the SYN (Synchronize) flag in TCP packets.
        'ACK': Flag indicating the ACK (Acknowledgment) flag in TCP packets.
        'FIN': Flag indicating the FIN (Finish) flag in TCP packets.
        'RST': Flag indicating the RST (Reset) flag in TCP packets.
        'Packets/Time': Indicates the rate of packets received per unit time.
        'Time Between Packets': Represents the time duration between consecutive packets.
        'target': Represents the classification label ('Normal' or other classification) based on certain conditions.'''
        fields_to_capture = []
        print("Enter fields to capture (comma-separated):")
        user_input = input().strip()
        fields_to_capture = [field.strip() for field in user_input.split(',')]

        self.start_time = time.time()
        self.packet_count = 0
        self.data_to_write = []

        cap = pyshark.LiveCapture(interface=self.iface_name)

        try:
            with open('test.csv', 'w', newline='') as csvfile:
                filewriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                filewriter.writerow(fields_to_capture + ['target'])

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

                            # Extract packet fields based on user input
                            captured_data = []
                            for field in fields_to_capture:
                                value = None
                                if field == 'Highest Layer':
                                    value = pkt.highest_layer
                                elif field == 'Transport Layer':
                                    value = transport_layer
                                elif field == 'Source IP':
                                    value = source_ip
                                elif field == 'Dest IP':
                                    value = target_ip
                                elif field == 'Source Port' and hasattr(pkt[pkt.transport_layer], 'srcport'):
                                    value = pkt[pkt.transport_layer].srcport
                                elif field == 'Dest Port' and hasattr(pkt[pkt.transport_layer], 'dstport'):
                                    value = pkt[pkt.transport_layer].dstport
                                elif field == 'Packet Length':
                                    value = pkt.length
                                elif field == 'SYN':
                                    value = syn_flag
                                elif field == 'ACK':
                                    value = ack_flag
                                elif field == 'FIN':
                                    value = fin_flag
                                elif field == 'RST':
                                    value = rst_flag
                                elif field == 'Packets/Time':
                                    value = packets_per_second_formatted
                                elif field == 'Time Between Packets':
                                    value = time_between_packets_ns
                                elif field == 'target':
                                    value = target

                                captured_data.append(value)

                            # Store the captured data into the data_to_write list
                            self.data_to_write.append(captured_data)

                            if self.packet_count >= self.capture_limit:
                                break

                        else:
                            transport_layer = 'ARP'
                            if pkt.arp.src_proto_ipv4 not in self.allowed_IP:
                                target = pkt.arp.src_proto_ipv4
                            else:
                                target = 'Normal'

                    except AttributeError as e:
                        pass

                    if self.packet_count >= self.capture_limit:
                        break

        except OSError as e:
            print("Error occurred:", e)
            sys.exit(1)

        # Save captured data to file
        self.save_data()
        print("Capturing completed and data saved.")

# Example usage:
packet_capturer = PacketCapture()
packet_capturer.capture_packets()
