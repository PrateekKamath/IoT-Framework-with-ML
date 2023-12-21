from network_security_library import SYN_DoS_DDoS
import signal
def main():
    # Initialize PacketCapture instance and handle KeyboardInterrupt
    attack_capture_instance = SYN_DoS_DDoS(iface_name='Wi-Fi')
    signal.signal(signal.SIGINT, attack_capture_instance.handle_interrupt)

    # Start capturing packets
    attack_capture_instance.capture_packets()
    attack_capture_instance.prediction()
    # Alternatively, you can call other methods/functions of PacketCapture class as needed
    # attack_capture_instance.train_capture_packets()
    # attack_capture_instance.train_kNN()
    # attack_capture_instance.test_kNN()
    

if __name__ == "__main__":
    main()
