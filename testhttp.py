#!/usr/bin/env python3

import network as Network
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(module)-12s %(threadName)-12s %(message)s -- %(filename)s:%(funcName)s:%(lineno)d', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

server = Network.Http("http://checkip.dyndns.com")

# TEXT sample
logger.debug("HTTP GET TEXT")
logger.debug("-------------")
logger.debug("TEXT: {}".format(server.get_text(timeout=0.0001)))
(code, reason) = server.response_status()
logger.debug("Status: {} - {}".format(code, reason))
logger.debug("-------------")
print('\n')

# JSON sample
logger.debug("HTTP GET JSON")
logger.debug("-------------")
json = server.get_json(url='http://httpbin.org/get', params={'firstargument':'firstvalue'})
(code, reason) = server.response_status()
logger.debug("Status: {} - {}".format(code, reason))
if json:
	logger.debug("JSON: {}".format(json))
	logger.debug("ORIGIN: {}".format(json['origin']))
else:
	logger.warning("No valid JSON received")
logger.debug("-------------")
print('\n')

# BINARY sample
logger.debug("HTTP GET BINARY")
logger.debug("-------------")
logger.debug("BINARY: {}".format(server.get_binary("http://httpbin.org/bytes/20")))
(code, reason) = server.response_status()
logger.debug("Status: {} - {}".format(code, reason))
logger.debug("-------------")
print('\n')
