import socket
import datetime
import socket
import json


class TCPOverUDP:
    def __init__(self, addr, port, type):
        self.addr = addr
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.seq_num = 0
        self.last_correct_seq = 0
        self.last_correct_ack = 0
        self.status_codes = {
            200: 'OK',
            404: 'NOT FOUND'
        }
        self.window_size = 5
        self.bufferSize = 256
        self.timeout = 1  # one second timeout
        if type == "Server":
            self.sock.bind((self.addr, self.port))

    def checksum(self, data):
        # Calculate the checksum of the data
        # You can use any checksum algorithm here
        # For simplicity, we'll use the sum of bytes
        return ~(sum(data) + 1)

    def threeway_handshake_client(self):
        packet = {
            'seq_num': self.seq_num,
            'ack_num': 0,
            # 'flags': flags,
            'flags': {'SYN': True, 'ACK': False, 'FIN': False},
            'data': b'',
            'length': 0
        }
        self.send_packet(packet, (self.addr, self.port))
        self.sock.settimeout(self.timeout)

        # Wait for a sync acknowledgment from the server
        flag = True
        while flag:
            try:
                ack, addr = self.recv_packet()

                # Check if the acknowledgment is correct
                if ack['flags']['SYN'] and ack['flags']['ACK']:
                    flag = False
                    break
            except socket.timeout:
                pass

            # If the acknowledgment is incorrect or not received, resend the packet
            if flag:
                self.send_packet(packet, (self.addr, self.port))

        packet = {
            'seq_num': self.seq_num,
            'ack_num': 0,
            # 'flags': flags,
            'flags': {'SYN': False, 'ACK': True, 'FIN': False},
            'data': b'',
            'length': 0
        }
        self.send_packet(packet, (self.addr, self.port))

    def threeway_handshake_server(self):
        packet, addr = self.sock.recvfrom(1024)
        packet = eval(packet.decode())

        if packet['flags']['SYN']:
            packet = {
                'seq_num': self.seq_num,
                'ack_num': 0,
                'flags': {'SYN': True, 'ACK': True, 'FIN': False},
                'data': b'',
                'length': 0
            }
            self.send_packet(packet, addr)
            self.sock.settimeout(self.timeout)

            # Wait for a sync acknowledgment from the server
            flag = True
            while flag:
                try:
                    ack, addr = self.recv_packet()

                    # Check if the acknowledgment is correct
                    if ack['flags']['ACK']:
                        flag = False
                        break
                except socket.timeout:
                    pass

                # If the acknowledgment is incorrect or not received, resend the packet
                if flag:
                    self.send_packet(packet, addr)

    def close_client(self):
        # send fin to the server
        packet = {
            'seq_num': self.seq_num,
            'ack_num': 0,
            'flags': {'SYN': False, 'ACK': False, 'FIN': True},
            'data': b'',
            'length': 0
        }
        self.send_packet(packet, (self.addr, self.port))
        self.sock.settimeout(self.timeout)

        # Wait for ack from the server
        flag = True
        while flag:
            try:
                ack, addr = self.recv_packet()

                # Check if the acknowledgment is correct
                if ack['flags']['ACK']:
                    flag = False
                    break
            except socket.timeout:
                pass
            # If the acknowledgment is incorrect or not received, resend the packet
            if flag:
                self.send_packet(packet, (self.addr, self.port))

        # Wait for fin from the server
        flag = True
        while flag:
            try:
                fin, addr = self.recv_packet()

                # Check if the acknowledgment is correct
                if fin['flags']['FIN']:
                    flag = False
                    break
            except socket.timeout:
                pass

        # send ack to the server
        packet = {
            'seq_num': self.seq_num,
            'ack_num': 0,
            'flags': {'SYN': False, 'ACK': True, 'FIN': False},
            'data': b'',
            'length': 0
        }
        self.send_packet(packet, (self.addr, self.port))
        self.sock.settimeout(1)
        # # Wait for 5 sec to check the server closed
        # flag = True
        # while flag:
        #     print("f")
        #     try:
        #         ack, addr = self.recv_packet()
        #         # Check if the acknowledgment is correct
        #         # print(ack['ack_num'], (packet['seq_num'] + packet['length']))
        #         # if ack['flags']['ACK']:
        #         #     flag = False
        #         #     print("leaving")
        #         #     break
        #     except socket.timeout:
        #         print("timeout")
        #         flag = False
        #     # If the acknowledgment is incorrect or not received, resend the packet
        #     if flag:
        #         self.send_packet(packet, (self.addr, self.port))
        self.sock.close()

    def close_server(self):
        # Wait for a fin from the client
        flag = True
        while flag:
            try:
                fin, addr = self.recv_packet()

                # Check if the acknowledgment is correct
                if fin['flags']['FIN']:
                    flag = False
                    break
            except socket.timeout:
                pass

        # send ack to the client
        packet = {
            'seq_num': self.seq_num,
            'ack_num': 0,
            # 'flags': flags,
            'flags': {'SYN': False, 'ACK': True, 'FIN': False},
            'data': b'',
            'length': 0
        }
        self.send_packet(packet, addr)
        self.sock.settimeout(self.timeout)

        # send fin to the client
        packet = {
            'seq_num': self.seq_num,
            'ack_num': 0,
            'flags': {'SYN': False, 'ACK': False, 'FIN': True},
            'data': b'',
            'length': 0
        }
        self.send_packet(packet, addr)
        self.sock.settimeout(self.timeout)

        # Wait for ack from the client
        flag = True
        while flag:
            try:
                ack, addr = self.recv_packet()
                # Check if the acknowledgment is correct
                if ack['flags']['ACK']:
                    flag = False
                    break
            except socket.timeout:
                pass
            # If the acknowledgment is incorrect or not received, resend the packet
            if flag:
                self.send_packet(packet, addr)

        self.sock.close()

    def send_packet(self, packet, addr):
        # Calculate the checksum of the packet
        packet['checksum'] = self.checksum(packet['data'])

        # Send the packet to the receiver
        self.sock.sendto(str(packet).encode(), addr)

    def recv_packet(self):
        # Wait for a packet from the receiver
        while True:
            packet, addr = self.sock.recvfrom(1024)
            packet = eval(packet.decode())

            # Check if the packet is not corrupted
            if packet['checksum'] == self.checksum(packet['data']):
                return packet, addr

    def send(self, flags, data, addr=None):
        if addr is None:
            addr = (self.addr, self.port)

        data = bytes(data, 'utf-8')
        # Divide the data into packets
        packets = [data[i:i + self.bufferSize] for i in range(0, len(data), self.bufferSize)]

        # Send the packets using the stop-and-wait protocol
        for i, packet_data in enumerate(packets):
            if i == (len(packets) - 1):
                flags['FIN'] = True
            packet = {
                'seq_num': self.seq_num,
                'ack_num': 0,
                'flags': flags,
                'data': packet_data,
                'length': len(packet_data)
            }

            self.send_packet(packet, addr)
            self.sock.settimeout(self.timeout)

            # Wait for an acknowledgment from the receiver
            flag = True
            while flag:
                try:
                    ack, addr = self.recv_packet()

                    # Check if the acknowledgment is correct
                    if ack['ack_num'] == (packet['seq_num'] + packet['length']) and ack['flags']['ACK']:
                        flag = False
                        break
                except socket.timeout:
                    pass

                # If the acknowledgment is incorrect or not received, resend the packet
                if flag:
                    self.send_packet(packet, (self.addr, self.port))

            self.seq_num += packet['length']

    def recv(self):
        # Receive data using the stop-and-wait protocol
        data = b''
        expected_seq_num = self.seq_num

        while True:
            # Wait for a packet from the sender
            packet, addr = self.recv_packet()

            # Check if the packet is the next one expected
            if packet['seq_num'] == expected_seq_num:
                data += packet['data']
                expected_seq_num += packet['length']

                # Send an acknowledgment to the sender
                ack = {
                    'seq_num': packet['ack_num'],
                    'ack_num': packet['seq_num'] + packet['length'],
                    'flags': {'SYN': False, 'ACK': True, 'FIN': False},
                    'data': b'',
                }
                self.last_correct_seq = packet['ack_num']
                self.last_correct_ack = packet['seq_num'] + packet['length']
                self.send_packet(ack, addr)

                # Check if all the data has been received
                if packet['flags']['FIN']:
                    break
            else:
                # Send an acknowledgment for the last correctly received packet
                ack = {
                    'seq_num': self.last_correct_seq,
                    'ack_num': self.last_correct_ack,
                    'flags': {'SYN': False, 'ACK': True, 'FIN': False},
                    'data': b'',
                }
                self.send_packet(ack)

        data = data.decode('utf-8')

        return data, addr

    def send_request(self, flags, data):
        self.threeway_handshake_client()

        # send request
        self.send(flags, data)

        self.reset()

        # receive response
        response, addr = self.recv()

        self.close_client()
        return response

    def handle_request(self):
        self.threeway_handshake_server()

        # receive request
        request, addr = self.recv()

        self.reset()
        # handle request
        response = self.handle_HTTP_request(request.encode())

        # send response
        flags = {'SYN': False, 'ACK': False, 'FIN': False}
        self.send(flags, response.decode('utf-8'), addr)

        self.close_server()
        return response

    def reset(self):
        self.seq_num = 0
        self.last_correct_seq = 0
        self.last_correct_ack = 0

    def handle_HTTP_request(self, request):
        # Parse the request method, path, and headers
        request_lines = request.decode('utf-8').split('\r\n')
        method, path, http_version = request_lines[0].split(' ')
        headers = {}
        body = ''
        for index, line in enumerate(request_lines[1:]):
            if line and (": " in line):
                key, value = line.split(': ')
                headers[key] = value
            else:
                if method != "POST":
                    break
                for lin in request_lines[index + 1:]:
                    body += lin
                body = json.loads(body)
                break

        # Handle the request based on the method and path
        if method == 'GET':
            response_data = self.handle_get_request(path)
        elif method == 'POST':
            response_data = self.handle_post_request(path, body)
        elif method == 'DELETE':
            response_data = self.handle_delete_request(path)
        elif method == "OPTIONS":
            response_data = {"message": "okay"}
        else:
            response_data = ''

        # Construct the response and send it back to the client
        response = self.construct_response(response_data)
        return response

    def handle_get_request(self, path):
        data = ''
        if path == '/getTasks':
            try:
                with open('DB/tasks.json', 'r') as f:
                    # Load the contents of the file as a dictionary
                    data = json.load(f)
            except:
                data = ''
        return data

    def handle_post_request(self, path, body):
        response = ''
        if path == '/addTask':
            try:
                with open('DB/tasks.json', 'r') as f:
                    # Load the contents of the file as a dictionary
                    data = json.load(f)

                data['tasks'].append(body['task'])
                with open("DB/tasks.json", "w") as f:
                    # Write the JSON data to the file
                    json.dump(data, f)
                response = {"message": "Task added successfully!!"}
            except:
                response = ''
        return response

    def handle_delete_request(self, full_path):
        response = ''
        path_details = full_path.split('/')
        path = path_details[1]
        index = int(path_details[2])
        if path == 'deleteTasks':
            try:
                with open('DB/tasks.json', 'r') as f:
                    # Load the contents of the file as a dictionary
                    data = json.load(f)

                if (index >= 0) and (index < len(data['tasks'])):
                    del data['tasks'][index]
                    with open("DB/tasks.json", "w") as f:
                        # Write the JSON data to the file
                        json.dump(data, f)

                    response = {"message": "Task deleted successfully!!"}
                else:
                    response = ''
            except:
                response = ''
        return response

    def construct_response(self, data):
        data = data if data == '' else json.dumps(data)

        # Construct an HTTP response with the given data
        status_code = 200 if len(data) else 404
        status_message = self.status_codes[status_code]
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Content-Length': str(len(data)),
            'Connection': 'close'
        }
        response_lines = [
            f'HTTP/1.1 {status_code} {status_message}',
            *[f'{key}: {value}' for key, value in headers.items()],
            '',
            data
        ]
        response = '\r\n'.join(response_lines).encode()
        return response
