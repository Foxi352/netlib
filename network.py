#!/usr/bin/env python3
# vim: set encoding=utf-8 tabstop=4 softtabstop=4 shiftwidth=4 expandtab
#########################################################################
#  Copyright 2017- Serge Wagener                     serge@wagener.family
#########################################################################
#  This file is part of SmartHomeNG
#
#  SmartHomeNG is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  SmartHomeNG is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with SmartHomeNG  If not, see <http://www.gnu.org/licenses/>.
#########################################################################

"""
This library contains the Network class for SmartHomeNG.

New network functions are going to be implemented in this library.

"""

import logging
import re
import ipaddress
import select
import socket
import threading
import time

# Usefull small network related functions. Some have been migrated from Utils lib
class Network(object):

    @staticmethod
    def is_mac(mac):
        """
        Validates a MAC address

        :param mac: MAC address
        :type string: str

        :return: True if value is a MAC
        :rtype: bool
        """

        mac = str(mac)
        if len(mac) == 12:
            for c in mac:
                try:
                    if int(c, 16) > 15:
                        return False
                except:
                    return False
            return True

        octets = re.split('[\:\-\ ]', mac)
        if len(octets) != 6:
            return False
        for i in octets:
            try:
                if int(i, 16) > 255:
                    return False
            except:
                return False
        return True

    @staticmethod
    def is_ip(string):
        """
        Checks if a string is a valid ip-address (v4 or v6)

        :param string: String to check
        :type string: str

        :return: True if an ip, false otherwise.
        :rtype: bool
        """

        return (Network.is_ipv4(string) or Network.is_ipv6(string))

    @staticmethod
    def is_ipv4(string):
        """
        Checks if a string is a valid ip-address (v4)

        :param string: String to check
        :type string: str

        :return: True if an ip, false otherwise.
        :rtype: bool
        """

        try:
            ipaddress.IPv4Address(string)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def is_ipv6(string):
        """
        Checks if a string is a valid ip-address (v6)

        :param string: String to check
        :type string: str

        :return: True if an ipv6, false otherwise.
        :rtype: bool
        """

        try:
            ipaddress.IPv6Address(string)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def is_hostname(string):
        """
        Checks if a string is a valid hostname

        The hostname has is checked to have a valid format

        :param string: String to check
        :type string: str

        :return: True if a hostname, false otherwise.
        :rtype: bool
        """

        try:
            return bool(re.match("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", string))
        except TypeError:
            return False

    @staticmethod
    def get_local_ipv4_address():
        """
        Get's local ipv4 address
        TODO: What if more than one interface present ?

        :return: IPv4 address as a string
        :rtype: string
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    @staticmethod
    def get_local_ipv6_address():
        """
        Get's local ipv6 address
        TODO: What if more than one interface present ?

        :return: IPv6 address as a string
        :rtype: string
        """
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            s.connect(('2001:4860:4860::8888', 1))
            IP = s.getsockname()[0]
        except:
            IP = '::1'
        finally:
            s.close()
        return IP


class tcp_client(object):

    def __init__(self, host, port, name=None, autoreconnect=True, connect_retries=5, connect_cycle=5, retry_cycle=30):
        """ Validates a MAC address

        :param host: Remote host name or ip address (v4 or v6)
        :param port: Remote host port to connect to
        :param name: Name of this connection (mainly for logging purposes)
        :param name: Should the socket try to reconnect on lost connection (or finished connect cycle)
        :param connect_retries: Number of connect retries per cycle
        :param connect_cycle: Time between retries inside a connect cycle
        :param retry_cycle: Time between cycles if :param:autoreconnect is True

        :type host: str
        :type port: int
        :type name: str
        :type name: bool
        :type connect_retries: int
        :type connect_cycle: int
        :type retry_cycle: int
        """
        self.logger = logging.getLogger(__name__)

        # Public properties
        self.name = name

        # "Private" properties (__ not used on purpose)
        self._host = host
        self._port = port
        self._autoreconnect = autoreconnect
        self._is_connected = False
        self._connect_retries = connect_retries
        self._connect_cycle = connect_cycle
        self._retry_cycle = retry_cycle
        self._timeout = 1
 
        self._hostip = None
        self._ipver = socket.AF_INET
        self._socket = None
        self._connect_counter = 0

        self._connected_callback = None
        self._disconnected_callback = None
        self._data_received_callback = None

        # "Secret" properties
        self.__connect_thread = None
        self.__connect_threadlock = threading.Lock()
        self.__receive_thread = None
        self.__receive_threadlock = threading.Lock()
        self.__running = True

        self.logger.setLevel(logging.DEBUG)
        self.logger.info("Initializing a connection to {} on TCP port {} {} autoreconnect".format(self._host, self._port, ('with' if self._autoreconnect else 'without')))
        
        # Test if host is an ip address or a host name
        if Network.is_ip(self._host):
            # host is an ip address (v4 or v6)
            self.logger.debug("{} is a valid IP address".format(host))
            self._hostip = self._host
            if Network.is_ipv6(self._host):
                self._ipver = socket.AF_INET6
            else:
                self._ipver = socket.AF_INET
        else:
            # host is a hostname, trying to resolve to ip address (v4 or v6)
            self.logger.debug("{} is not a valid IP address, trying to resolve it as hostname".format(host))
            try:
                self._ipver, sockettype, proto, canonname, socketaddr = socket.getaddrinfo(host, None)[0]
                # Check if resolved address is IPv4 or IPv6
                if self._ipver == socket.AF_INET:
                    # is IPv4
                    self._hostip, port = socketaddr               
                elif self._ipver == socket.AF_INET6:
                    # is IPv6
                    self._hostip, port, flow_info, scope_id = socketaddr
                else:
                    # This should never happen
                    self.logger.error("Unknown ip address family {}".format(self._ipver))
                    self._hostip = None
                # Print ip address if has been resolved
                if self._hostip is not None:
                    self.logger.info("Resolved {} to {} address {}".format(self._host, 'IPv6' if self._ipver == socket.AF_INET6 else 'IPv4', self._hostip))        
            except:
                # Impossible to resolve hostname to ip address
                self.logger.error("Cannot resolve {} to a valid ip address (v4 or v6)".format(self._host))
                self._hostip = None

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self,name):
        self.__name = name

    # Set callbacks
    def set_callbacks(self, connected=None, data_received=None, disconnected=None):
        """ Set callbacks to caller for different socket events

        :param connected: Called whenever a connection is established successfully
        :param data_received: Called when data is received
        :param disconnected: Called when a connection has been dropped for whatever reason

        :type connected: function
        :type data_received: function
        :type disconnected: function
        """
        self._connected_callback=connected
        self._disconnected_callback=disconnected
        self._data_received_callback=data_received

    # Function that starts the connection cycle
    def connect(self):
        """ Connects the socket

        :return: False if an error prevented us from launching a connection thread. True if connection thread will be started.
        :rtype: bool
        """
        # return immediatly if no valid ip has been found in __init__
        if self._hostip is None:
            self.logger.error("No valid IP address to connect to {}".format(self._host))
            self._is_connected = False
            return False
        if self._is_connected:
            self.logger.error("Already connected to {}, ignoring new request".format(self._host))
            return False
            
        self.__connect_thread = threading.Thread(target=self._connect_thread_worker, name='TCP_Connect') #name='connect-{}:{}'.format(self._host, self._port))
        self.__connect_thread.daemon = True
        self.__connect_thread.start()
        return True
        
    # Return connected state
    def connected(self):
        """ Returns the current connection state

        :return: True if an active connection exists,else False.
        :rtype: bool
        """
        return self._is_connected

    # Send string to open connection
    def send(self, msg):
        if self._is_connected:
            self._socket.send(msg.encode('utf-8'))
        else:
            self.logger.warning("No connection to {}, cannot send data {}".format(self._host, msg))

    def _connect_thread_worker(self):
        if not self.__connect_threadlock.acquire(blocking=False):
            self.logger.warning("Connection attempt already in progress for {}, ignoring new request".format(self._host))
            return
        if self._is_connected:
            self.logger.error("Already connected to {}, ignoring new request".format(self._host))
            return
        self.logger.debug("Starting connection cycle for {}".format(self._host))
        self._connect_counter = 0
        while self.__running and not self._is_connected:
            # Try a full connect cycle
            while not self._is_connected and self._connect_counter < self._connect_retries and self.__running:
                self._connect()
                if self._is_connected:
                    try:
                        self.__connect_threadlock.release()
                        if self._connected_callback is not None:
                            #self.logger.debug(self)
                            self._connected_callback(self)
                        self.__receive_thread = threading.Thread(target=self._receive_thread_worker, name='TCP_Receive') #name='connect-{}:{}'.format(self._host, self._port))
                        self.__receive_thread.daemon = True
                        self.__receive_thread.start()
                    except:
                        raise
                    return True
                self._wait(self._connect_cycle)

            if self._autoreconnect:
                self._wait(self._retry_cycle)
                self._connect_counter = 0
            else:
                break;
        try:
            self.__connect_threadlock.release()
        except:
            pass

    # Connect to server
    def _connect(self):
        self.logger.debug("Connecting to {} using {} {} on TCP port {} {} autoreconnect".format(self._host, 'IPv6' if self._ipver == socket.AF_INET6 else 'IPv4', self._hostip, self._port, ('with' if self._autoreconnect else 'without')))
        # Try to connect to remote host using ip (v4 or v6)
        try:
            self._socket = socket.socket(self._ipver, socket.SOCK_STREAM)
            self._socket.setsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self._socket.settimeout(5)
            self._socket.connect(('{}'.format(self._hostip), int(self._port)))
            self._socket.settimeout(self._timeout)
            self._is_connected = True
            self.logger.info("Connected to {} on TCP port {}".format(self._host, self._port))
        # Connection error
        except Exception as err:
            self._is_connected = False
            self._connect_counter += 1
            self.logger.warning("TCP connection to {}:{} failed with error {}. Counter: {}/{}".format(self._host, self._port, err, self._connect_counter, self._connect_retries))

    # Wait for data and process them
    def _receive_thread_worker(self):
        poller = select.poll()
        poller.register(self._socket, select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR)
        
        while self._is_connected and self.__running:
            events = poller.poll(1000)
            for fd, event in events:
                if event & select.POLLHUP:
                    self.logger.warning("Client socket closed")
                if event & (select.POLLIN | select.POLLPRI):
                    msg = self._socket.recv(4096)
                    if msg:
                        if self._data_received_callback is not None:
                            self._data_received_callback(self, str.rstrip(str(msg,'utf-8')))
                    else:
                        # Peer connection closed
                        self.logger.warning("Connection closed by peer {}".format(self._host))
                        self._is_connected = False
                        poller.unregister(self._socket)
                        if self._disconnected_callback is not None:
                            self._disconnected_callback(self)
                        if self._autoreconnect:
                            self.logger.debug("Autoreconnect enabled for {}".format(self._host))
                            self.connect()
 
    # replaces time.sleep() and exits when SHNG is stopped
    def _wait(self, time_lapse):
        time_start = time.time()
        time_end = (time_start + time_lapse)
        while self.__running and time_end > time.time():
            pass
    # Clean our mess on close down
    def close(self):
        self.logger.info("Closing connection to {} on TCP port {}".format(self._host, self._port))
        self.__running = False
        if self.__connect_thread is not None and self.__connect_thread.isAlive():
            self.__connect_thread.join()
        if self.__receive_thread is not None and self.__receive_thread.isAlive():
            self.__receive_thread.join()
