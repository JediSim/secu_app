import socket
import ssl
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Params client
HOST = 'www.pirate.fr' 
PORT = 443

try:
    # Création du socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    # SSL
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # Verify Root
    context.load_verify_locations(cafile='root_ca.cert.pem')

    # Socket secure
    secure_client_socket = context.wrap_socket(client_socket, server_hostname=HOST)

    # Get serv certif
    server_cert_bytes = secure_client_socket.recv(4096)
    server_cert = x509.load_pem_x509_certificate(
        server_cert_bytes, default_backend())

    # Verif certif
    print(f"Certificat du serveur décodé:\n{server_cert}")

    # Extraction nom de dommaine
    common_name = server_cert.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME)[0].value

    # Verif avec HOST
    if common_name != HOST:
        raise ValueError(f"Le Common Name (CN) du certificat ne correspond pas à {HOST}")

    # Debut de communication secure
    while True:
        message = input("Client: ")
        secure_client_socket.send(message.encode('utf-8'))

        data = secure_client_socket.recv(1024).decode('utf-8')
        print(f"Serveur: {data}")

except Exception as e:
    print(f"Erreur: {e}")

finally:
    # Fin de connexion
    if 'secure_client_socket' in locals():
        secure_client_socket.close()
