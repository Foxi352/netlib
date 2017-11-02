#!/usr/bin/env python3

import network
import logging
import time
import signal
import sys

running = True

def signal_handler(signal, frame):
    global running
    logger.debug('You pressed Ctrl+C!')
    running = False

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

signal.signal(signal.SIGINT, signal_handler)

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(module)-12s %(threadName)-12s %(message)s -- %(filename)s:%(funcName)s:%(lineno)d', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

logger.debug("Test started")

apache = network.Tcp_client(name='Apache', host='192.168.1.5', port=80, autoreconnect=False, connect_cycle=1, retry_cycle=5)
apache.set_callbacks(connected=connected_callback, disconnected=disconnected_callback, data_received=receive_callback)
apache.connect()

netcat = network.Tcp_client(name='NetCat', host='127.0.0.1', port=5555, autoreconnect=True, connect_cycle=1, retry_cycle=5)
netcat.set_callbacks(connected=connected_callback, disconnected=disconnected_callback, data_received=receive_callback)
netcat.terminator='e'
netcat.connect()


while running:
    time.sleep(0.25)

logger.debug("Ending...")
    
apache.close()
netcat.close()

logger.debug("Test ended")
