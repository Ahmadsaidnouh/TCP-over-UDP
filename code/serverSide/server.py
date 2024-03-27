from TCPOverUDP import TCPOverUDP
while True:
    UDP_IP = "127.0.0.1"
    UDP_PORT = 5005
    server = TCPOverUDP(UDP_IP, UDP_PORT, "Server")

    # server is listening for any requests
    server.handle_request()
