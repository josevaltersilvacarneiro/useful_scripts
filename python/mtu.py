#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# This script is an adaptation of
#   https://github.com/brandon-rhodes/fopnp/blob/m/py3/chapter02/big_sender.py
#
# mtu.py - It sends a big UDP datagram to know the MTU
#   of the network's path.
#
# Author            - José V S Carneiro
#
# ------------------------------------------------------------------
#
# Examples:
#   $ mtu.py 8.8.8.8
#   $ mtu.py 8.8.8.8 -p 53
#
# ------------------------------------------------------------------
#
# History:
#
#       Version 0.1 2023-04-10, José V S Carneiro, git@josevaltersilvacarneiro.net
#           - First Adaptation
#
# Copyright: GPLv3

from __future__ import print_function

import argparse
import socket
import sys

if sys.version_info.major == 3 and sys.version_info.minor > 6:

    if sys.platform != 'linux':
        print("Unsupported: can only perform MTU discovery on linux", 
            file=sys.stderr)

        sys.exit(1)

    class IN:
        IP_MTU          = 14
        IP_MTU_DISCOVER = 10
        IP_PMTUDISC_DO  = 2
else:
    import IN

    if not hasattr(IN, 'IP_MTU'):
        raise RuntimeError('cannot perform MTU discovery on this combination \
            of operating system and Python distribution')

def send_big_datagram(host, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, IN.IP_MTU_DISCOVER, IN.IP_PMTUDISC_DO)
    sock.connect((host, port))

    try:
        sock.send(b'#' * 6500)
    except socket.error:
        print('Alas, the datagram did not make it')
        max_mtu = sock.getsockopt(socket.IPPROTO_IP, IN.IP_MTU)
        print('Actual MTU: {}'.format(max_mtu))
    else:
        print('The big datagram was sent!')

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Send UDP packet to get MTU')

    parser.add_argument(
        'host',
        help='the host to which to target the packet'
    )

    parser.add_argument(
        '-p',
        metavar='PORT',
        help='UDP port (default 1060)',
        type=int,
        default=1060
    )

    args = parser.parse_args()

    send_big_datagram(args.host, args.p)
