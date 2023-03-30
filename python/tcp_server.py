#!/bin/env python2
# -*- coding: UTF-8 -*-
#
# tcp_server.py - It receives some data and sends back an ACK!
#
# Author        - José V S Carneiro
#
# ------------------------------------------------------------
#
# This script receives as parameters the target host and the
#   target port.
#
# Examples:
#       $ tcp_server.py
#       $ tcp_server.py --bind_ip 0.0.0.0 --bind_port 9999
#
# ------------------------------------------------------------
#
# History:
#
#       Version 0.1 2023-03-30, José V S Carneiro, git@josevaltersilvacarneiro.net
#       - First Version
#
# Copyright: GPLv3

import argparse

import socket
import threading

def handle_client(client_socket):
    
    # shows what the client sends
    request = client_socket.recv(1024)

    print "[*] Received: %s" % request

    # sends a packet back
    client_socket.send("ACK!")

    client_socket.close()

def main(bind_ip, bind_port):
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.bind((bind_ip, bind_port))

    server.listen(5)

    print "[*] Listening on %s:%d" % (bind_ip, bind_port)

    while True:

        client, addr = server.accept()

        print "[*] Accepted connection from: %s:%d" % (addr[0], addr[1])

        # trigers thread
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

if __name__ == '__main__':
    """This script accepts some data, prints it and sends it back `ACK!`"""

    parser = argparse.ArgumentParser(
        description='tcp server'
    );

    parser.add_argument(
        '--bind_ip',
        type=str,
        help='which interface to listen',
        default='0.0.0.0'
    );

    parser.add_argument(
        '--bind_port',
        type=int,
        help='which port to listen',
        default=9999
    );

    args = parser.parse_args()

    bind_ip     = args.bind_ip
    bind_port   = args.bind_port

    main(bind_ip, bind_port)
