#!/bin/env python2
# -*- coding: UTF-8 -*-
#
# udp_client.py - It sends some data and receives some content 
#   using udp sockets.
#
# Author        - José V S Carneiro
#
# ------------------------------------------------------------
#
# This script receives as parameters the target host and the
#   target port.
#
# Examples:
#       $ udp_client --target_host 8.8.8.8
#       $ udp_client --target_host 1.1.1.1 --target_port 53
#
# ------------------------------------------------------------
#
# History:
#
#       Version 0.1 2023-03-28, José V S Carneiro, git@josevaltersilvacarneiro.net
#       - First Version
#
# Copyright: GPLv3

import argparse
import socket

def main(host, port):
    """Main function"""

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);

    client.sendto("AAABBBCCC", (host, port))

    data, addr = client.recvfrom(512)

    print data

if __name__ == '__main__':
    """This script sends some data and receives some content"""

    parser = argparse.ArgumentParser(
                description='udp client'
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
                default=53
            );

    args = parser.parse_args()

    host = args.target_host
    port = args.target_port

    main(host, port)
