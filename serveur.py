import socket
import ssl

# Server parameters
HOST = '127.0.0.1'
PORT = 443
CERTFILE = 'serveur_http.cert.pem'
KEYFILE = 'serveur_http.pem'

# Create server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()

print(f"Server listening on {HOST}:{PORT}")

# Initialize secure_client_socket outside the try block
secure_client_socket = None

try:
    # Wait for client connection
    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")

    # Wrap socket in SSL
    secure_client_socket = ssl.wrap_socket(
        client_socket, keyfile=KEYFILE, certfile=CERTFILE, server_side=True, cert_reqs=ssl.CERT_NONE)

    # Send server certificate to the client
    with open(CERTFILE, 'rb') as cert_file:
        server_cert_bytes = cert_file.read()

    secure_client_socket.send(server_cert_bytes)

    while True:
        # Wait for data from the client
        data = secure_client_socket.recv(1024).decode('utf-8')

        if not data:
            break

        print(f"Client: {data}")

        # Respond to the client
        message = input("Server: ")
        secure_client_socket.send(message.encode('utf-8'))

except ssl.SSLError as e:
    print(f"An SSL error occurred: {e}")

except Exception as e:
    print(f"An unexpected error occurred: {e}")

finally:
    # Close connections
    if secure_client_socket:
        secure_client_socket.close()

    server_socket.close()
