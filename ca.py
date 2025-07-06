import socket
import ssl

import socket
import threading
import time
import random

import hashlib
from sympy import randprime
from sympy.core.numbers import mod_inverse

# Table configuration
current_table = {}
old_table = {}
current_table_id = 0
lock = threading.Lock()

# Refresh and grace periods
REFRESH_INTERVAL = 50  
GRACE_PERIOD = 40      
INDEX_COUNT = 16       
P_BITS = 64            
X_BITS = 32            

# Store verified server cert fingerprints
verified_fingerprints = set()

def generate_random_prime(bits):
    return randprime(2**(bits - 1), 2**bits)

def refresh_ca_table():
    global current_table, old_table, current_table_id
    new_table = {}
    for index in range(INDEX_COUNT):
        while True:
            try:
                P = generate_random_prime(P_BITS)
                X = random.randint(2, P - 1)
                X_inv = mod_inverse(X, P)
                new_table[index] = (X, X_inv, P)
                break 
            except ValueError:

                continue

    with lock:
        old_table = current_table.copy()
        current_table = new_table
        current_table_id = 1 - current_table_id
        print(f"CA Table refreshed.")
    threading.Timer(GRACE_PERIOD, clear_old_table).start()

def clear_old_table():
    global old_table
    with lock:
        old_table.clear()

def start_refresh_thread():
    refresh_ca_table()
    def refresh_loop():
        while True:
            refresh_ca_table()
            time.sleep(REFRESH_INTERVAL)
    
    threading.Thread(target=refresh_loop, daemon=True).start()


def get_cert_fingerprint(cert_path):
    import hashlib
    with open(cert_path, 'rb') as f:
        pem_data = f.read()
    der_cert = ssl.PEM_cert_to_DER_cert(pem_data.decode())
    return hashlib.sha256(der_cert).hexdigest()

def load_verified_cert(cert_path):
    fingerprint = get_cert_fingerprint(cert_path)
    verified_fingerprints.add(fingerprint)

def start_ca_server():
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.bind(('0.0.0.0', 65433))
    raw_socket.listen(5)
    print("CA is listening")

    base_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    base_context.load_cert_chain(certfile='certs/server_cert.pem', keyfile='certs/server_key.pem')
    # base_context.verify_mode = ssl.CERT_NONE
    base_context.verify_mode = ssl.CERT_REQUIRED
    base_context.check_hostname = False

    try:
        while True:
            conn, addr = raw_socket.accept()
            try:
                peek_data = conn.recv(1024, socket.MSG_PEEK).decode(errors='ignore')

                if peek_data.startswith("DEC"):
                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    context.load_cert_chain(certfile='certs/server_cert.pem', keyfile='certs/server_key.pem')
                    context.load_verify_locations(cafile='certs/ca_cert.pem')
                    context.verify_mode = ssl.CERT_REQUIRED
                else:
                    context = base_context

                tls_conn = context.wrap_socket(conn, server_side=True)

                if peek_data.startswith("DEC"):
                    cert = tls_conn.getpeercert(binary_form=False)
                    der_cert = tls_conn.getpeercert(binary_form=True)
                    if der_cert is None:
                        response = "Error: Certificate required for decryption request."
                        tls_conn.sendall(response.encode())
                        tls_conn.close()
                        continue
                    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
                    fingerprint = get_cert_fingerprint(pem_cert)
                    if fingerprint not in verified_fingerprints:
                        verified_fingerprints.add(fingerprint)

                    subject = dict(x[0] for x in cert['subject'])
                    common_name = subject.get('commonName', 'Unknown')

                data = tls_conn.recv(1024).decode().strip()

                if data.startswith("ENC"):
                    _, index_str = data.split(',')
                    index = int(index_str)
                    with lock:
                        if index in current_table:
                            X, X_inv, P = current_table[index]
                            response = f"{X},{X_inv},{P},{current_table_id}"
                        else:
                            response = "Invalid index"

                elif data.startswith("DEC"):
                    _, index_str, table_id_str = data.split(',')
                    index = int(index_str)
                    table_id = int(table_id_str)
                    with lock:
                        if table_id == current_table_id and index in current_table:
                            X, X_inv, P = current_table[index]
                            response = f"{X},{X_inv},{P}"
                        elif table_id == (1 - current_table_id) and index in old_table:
                            X, X_inv, P = old_table[index]
                            response = f"{X},{X_inv},{P}"
                        else:
                            response = "Invalid index"
                else:
                    response = "Error: Unknown request type"

                tls_conn.sendall(response.encode())
                print("Closing TLS connection.")
                tls_conn.close()

            except ssl.SSLError as ssl_err:
                print(f"TLS handshake failed: {ssl_err}")
                conn.close()

    except KeyboardInterrupt:
        print("CA Server shutting down.")
    finally:
        raw_socket.close()

if __name__ == "__main__":
    load_verified_cert('certs/server_cert.pem')
    start_refresh_thread()
    start_ca_server() 
