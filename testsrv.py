#!/usr/bin/env python3

import network as Network
import logging
import time
import signal
import sys

running = True

def signal_handler(signal, frame):
    global running
    logger.debug('You pressed Ctrl+C!')
    running = False

signal.signal(signal.SIGINT, signal_handler)

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(module)-12s %(threadName)-12s %(message)s -- %(filename)s:%(funcName)s:%(lineno)d', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

logger.debug("Server test started")

##
## Example calls and tests start below
##

def connected_callback(client):
    logger.debug("CALLBACK: {} connected".format(client.name))
    if client == apache:
        client.send("GET /\n")
    else:
        client.send("Hello {}\n".format(client.name))

def disconnected_callback(client):
    logger.debug("CALLBACK: {} disconnected".format(client.name))

def receive_callback(client, data):
    logger.debug("CALLBACK: received from {}: {}".format(client.name,data))

server = Network.tcp_server(port=80)
#server.set_callbacks(connected=connected_callback, disconnected=disconnected_callback, data_received=receive_callback)
server.start()


while running:
    time.sleep(0.25)

logger.debug("Ending...")
    
server.close()

logger.debug("Test ended")
