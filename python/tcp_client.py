#!/bin/env python2
# -*- coding: UTF-8 -*-
#
# tcp_client.py - It sends some data and receives some content 
#   using tcp sockets.
#
# Author        - José V S Carneiro
#
# ------------------------------------------------------------
#
# This script receives as parameters the target host and the
#   target port.
#
# Examples:
#       $ tcp_client --target_host www.google.com
#       $ tcp_client --target_host www.facebook.com --target_port 80
#
# ------------------------------------------------------------
#
# History:
#
#       Version 0.1 2023-03-27, José V S Carneiro, git@josevaltersilvacarneiro.net
#       - First Version
#
# Copyright: GPLv3

import argparse
import socket

def main(host, port):
    """Main function"""

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM);

    client.connect((host, port))

    client.send("GET / HTTP/1.1\r\nHost: %s\r\n\r\n" %host)

    response = client.recv(4096)

    print response

if __name__ == '__main__':
    """This script sends some data and receives some content"""

    parser = argparse.ArgumentParser(
                description='tcp client'
            );

    parser.add_argument(
                '--target_host',
                type=str,
                help='The host to which you want to connect',
                required=True
            );

    parser.add_argument(
                '--target_port',
                type=int,
                help='The port to which yout want to connect',
                default=80
            );

    args = parser.parse_args()

    host = args.target_host
    port = args.target_port

    main(host, port)
