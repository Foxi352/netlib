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

def listening_callback(server):
    logger.debug("CALLBACK: {} listening".format(server.name))

def incoming_connection_callback(server,client):
    logger.debug("CALLBACK: incoming connection on {} from {}".format(server.name, client[0]))

def disconnected_callback(server,client):
    logger.debug("CALLBACK: {} disconnected".format(client))

def receive_callback(server, client, data):
    logger.debug("CALLBACK: received from {}: {}".format(client,data))

server = Network.tcp_server(port=5555,name='TEST')
server.set_callbacks(   listening=listening_callback, 
                        incoming_connection=incoming_connection_callback,
                        disconnected=disconnected_callback,
                        data_received=receive_callback)
server.start()


while running:
    time.sleep(0.25)

logger.debug("Ending...")
    
server.close()

logger.debug("Test ended")
