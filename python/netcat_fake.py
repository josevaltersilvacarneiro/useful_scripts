#!/bin/env python2
# -*- coding: UTF-8 -*-
#
# netcat_fake.py - It simulates some of the functionality of
#   the netcat - to install it on Debian, use `apt install
#   netcat` - tool.
#
# Author         - José V S Carneiro
#
# ------------------------------------------------------------------
#
# To learn how to run it, use the following command:
#   netcat_fake.py --help
#
# Examples:
#   netcat_fake.py -l -p 9999 -c        # your server
#   netcat_fake.py -t localhost -p 9999 # your client
#
# With the above example, you will have a remote shell where you can
#   execute commands according to the server's privilege.
#
# ------------------------------------------------------------------
#
# History:
#
#       Version 0.1 2023-03-29, José V S Carneiro git@josevaltersilvacarneiro.net
#           - First Version
#
# Copyright: GPLv3

from __future__ import print_function

import sys
import socket
import getopt
import threading
import subprocess

listen              = False
command             = False
upload              = False
execute             = ""
target              = ""
upload_destination  = ""
port                = 0

def usage():
    print("Netcat Fake")
    print()
    print("Usage: netcat_fake.py -t target_host -p host")
    print("-l --listen                  - listen on [host]:[port] for incoming connections")
    print("-e --execute=file_to_run     - execute the given file upon receiving a connection")
    print("-c --command                 - initialize a command shell")
    print("-u --upload=destination      - upon receiving connection upload a file and write to [destination]")
    print()
    print()
    print("Examples: ")
    print("netcat_fake.py -t 192.168.0.1 -p 5555 -l -c")
    print("netcat_fake.py -t 192.168.0.1 -p 5555 -l -u=~/target")
    print("netcat_fake.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\"")
    print("echo 'ABCDEFGHI' | netcat_fake.py -t 192.168.11.12 -p 135")

    sys.exit(0)

def client_handler(client_socket):
    global upload
    global execute
    global command

    # checks if it's upload
    if len(upload_destination):

        # reads all the bytes and stores them to our target
        file_buffer = ""

        # keeps reading the data until none is available
        while True:
            data = client_socket.recv(1024)

            if not data:
                break
            else:
                file_buffer += data

            # we'll try to record them
            try:
                file_descriptor = open(upload_destination, "wb")
                file_descriptor.write(file_buffer)
                file_descriptor.close()

                # confirms that we recorded
                client_socket.send("Successfully saved file to %s\r\n" % upload_destination)

            except:
                client_socket.send("Failed to save file to %s\r\n" % upload_destination)

    # checks to see if it's command execution
    if len(execute):
                
        # run the command
        output = run_command(execute)

        client_socket.send(output)

    # enters another loop if a command shell is requested
    if command:

        # shows a command prompt
        client_socket.send("<NETCAT_FAKE:#> ")
        
        while True:

            # now we receive data until we get an enter key
            cmd_buffer = ""

            while "\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)

            # sends a back the output of the command
            response = run_command(cmd_buffer)

            # responds to the client
            client_socket.send(response + "<NETCAR_FAKE:#> ")

def server_loop():
    global target

    # if there is no target defined we'll listen all interfaces
    if not len(target):
        target = "0.0.0.0"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target, port))
    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        # triggers a thread to handle of our new client
        client_thread = threading.Thread(target=client_handler, args=(client_socket,))
        client_thread.start()

def run_command(command):

    # rm line break
    command = command.rstrip()

    # it runs a command and gets the output data
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except:
        output = "Failed to execute command.\r\n"

    # sends the output data back to the client
    return output

def client_sender(buffer):

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # connect to the target host
        client.connect((target, port))

        if len(buffer):
            client.send(buffer)

        while True:

            # now wait to get data back
            recv_len = 1
            response = ""

            while recv_len:

                data        = client.recv(4096)
                recv_len    = len(data)
                response   += data

                if recv_len < 4096:
                    break

            print(response, end='')

            # waits for more input data
            buffer  = raw_input("")
            buffer += "\n"

            # sends the data
            client.send(buffer)
    except:

        print("[*] Exception! Exiting.")

        # close the connection
        client.close()

def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target

    if not len(sys.argv[1:]):
        usage()

    # reads command line options

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu",
                ["help", "listen", "execute", "target", "port", "command", "upload"])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            listen = True
        elif o in ("-e", "--execute"):
            execute = a
        elif o in ("-c", "--commandshell"):
            command = True
        elif o in ("-u", "--upload"):
            upload_destination = a
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-p", "--port"):
            port = int(a)
        else:
            assert False, "Unhandled Option"

    # will we listen or just send data from stdin?
    if not listen and len(target) and port > 0:

        # reads the buffer
        buffer = sys.stdin.read()

        # send data off
        client_sender(buffer)

    # we will listen the door
    # we will upload, we'll execute commands
    # we will leave a shell

    if listen:
        server_loop()

if __name__ == '__main__':
    main()
