import socket
from TCPOverUDP import TCPOverUDP

HOST = 'localhost'
PORT = 10000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (HOST, PORT)
server.bind((HOST, PORT))
server.listen()

while True:
    # TCP connection with the browser
    connection, client_address = server.accept()

    # receive the HTTP request from the browser
    data = connection.recv(1024)
    data_decoded = data.decode()
    if "HTTP/" not in data_decoded:
        # print("faulty packet")
        connection.close()
        continue

    # sending the HTTP request to the server to be processed and handled using TCPOverUDP
    UDP_IP = "127.0.0.1"
    UDP_PORT = 5005
    TCPOverUDP_server = TCPOverUDP(UDP_IP, UDP_PORT, "Client")
    flags = {'SYN': False, 'ACK': False, 'FIN': False}
    response = TCPOverUDP_server.send_request(flags, data_decoded)

    # Sending the HTTP response back to the browser
    response = bytes(response, "utf-8")
    connection.sendall(response)
    connection.close()

server.close()