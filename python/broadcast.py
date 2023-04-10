#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# This script is an adaptation of
#   https://github.com/brandon-rhodes/fopnp/blob/m/py3/chapter02/udp_broadcast.py
#
# broadcast.py - Client and server UDP for sending of
#   broadcast messages in a LAN.
#
# Author:           - José V S Carneiro
#
# ------------------------------------------------------------------
#
# Examples:
#   $ broadcast.py server ""            # your server
#   $ broadcast.py client "<broadcast>" # your client
#
# ------------------------------------------------------------------
#
# History:
#
#       Version 0.1 2023-04-10, José V S Carneiro, git@josevaltersilvacarneiro.net
#           - First adaptation
#
# Copyright: GPLv3

from __future__ import print_function

import argparse
import socket

BUFSIZE = 6535

def server(interface, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((interface, port))
    print("Listening for datagrams at {}".format(sock.getsockname()))

    while True:
        data, address = sock.recvfrom(BUFSIZE)
        text = data.decode('ascii')
        print('The client at {} says'.format(address, text))

def client(network, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    text = 'Hello, world!'
    sock.sendto(text.encode('utf-8'), (network, port))

if __name__ == '__main__':
    choices = {'client' : client, 'server' : server}

    parser = argparse.ArgumentParser(description='Send, received UDP broadcast')

    parser.add_argument(
        'role', choices=choices, help='which role to take'
    )
    parser.add_argument(
        'host', help='interface the server listens at network the client sends to'
    )
    parser.add_argument(
        '-p',
        metavar='port',
        help='UDP port (default 1060)',
        type=int,
        default=1060
    )

    args = parser.parse_args()
    func = choices[args.role]

    func(args.host, args.p)
