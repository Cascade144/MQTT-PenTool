"""
File: controllerDriver.py
By: Gustavo Chavez
"""

# IMPORTS ###
import argparse
import sys

# LOCAL IMPORTS ###
from scanner import arp_scan, port_scan

# GLOBALS ###
header = '*******************************************'


def main():
    print(header)
    print('This is a pen tool for MQTT')
    print(header)
    if len(sys.argv) == 1:
        print('Usage: python3 pen_driver.py [-s]')
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', action='store_true')
    args = parser.parse_args()
    if args.s:
        print('Beginning scan for MQTT Brokers.')
        arp_scan()
        print('Attempting to find default port 1883 and 8883 open on responsive hosts.')
        port_scan()

    

if __name__ == '__main__':
    main()
