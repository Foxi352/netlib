#!/usr/bin/env python3
# vim: set encoding=utf-8 tabstop=4 softtabstop=4 shiftwidth=4 expandtab
#########################################################################
#  Parts Copyright 2016 C. Strassburg (lib.utils)     c.strassburg@gmx.de
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
import urllib3
import queue


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
    """ Initializes a new instance of tcp_client

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

    def __init__(self, host, port, name=None, autoreconnect=True, connect_retries=5, connect_cycle=5, retry_cycle=30):
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
            # host is a valid ip address (v4 or v6)
            self.logger.debug("{} is a valid IP address".format(host))
            self._hostip = self._host
            if Network.is_ipv6(self._host):
                self._ipver = socket.AF_INET6
            else:
                self._ipver = socket.AF_INET
        else:
            # host is a hostname, trying to resolve to an ip address (v4 or v6)
            self.logger.debug("{} is not a valid IP address, trying to resolve it as hostname".format(host))
            try:
                self._ipver, sockettype, proto, canonname, socketaddr = socket.getaddrinfo(host, None)[0]
                # Check if resolved address is IPv4 or IPv6
                if self._ipver == socket.AF_INET: # is IPv4
                    self._hostip, port = socketaddr
                elif self._ipver == socket.AF_INET6: # is IPv6
                    self._hostip, port, flow_info, scope_id = socketaddr
                else:
                    # This should never happen
                    self.logger.error("Unknown ip address family {}".format(self._ipver))
                    self._hostip = None
                # Print ip address on successfull resolve
                if self._hostip is not None:
                    self.logger.info("Resolved {} to {} address {}".format(self._host, 'IPv6' if self._ipver == socket.AF_INET6 else 'IPv4', self._hostip))
            except:
                # Unable to resolve hostname
                self.logger.error("Cannot resolve {} to a valid ip address (v4 or v6)".format(self._host))
                self._hostip = None

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, name):
        self.__name = name

    def set_callbacks(self, connected=None, data_received=None, disconnected=None):
        """ Set callbacks to caller for different socket events

        :param connected: Called whenever a connection is established successfully
        :param data_received: Called when data is received
        :param disconnected: Called when a connection has been dropped for whatever reason

        :type connected: function
        :type data_received: function
        :type disconnected: function
        """
        self._connected_callback = connected
        self._disconnected_callback = disconnected
        self._data_received_callback = data_received

    def connect(self):
        """ Connects the socket

        :return: False if an error prevented us from launching a connection thread. True if a connection thread has been started.
        :rtype: bool
        """
        if self._hostip is None: # return False if no valid ip to connect to
            self.logger.error("No valid IP address to connect to {}".format(self._host))
            self._is_connected = False
            return False
        if self._is_connected: # return false if already connected
            self.logger.error("Already connected to {}, ignoring new request".format(self._host))
            return False

        self.__connect_thread = threading.Thread(target=self._connect_thread_worker, name='TCP_Connect')
        self.__connect_thread.daemon = True
        self.__connect_thread.start()
        return True

    def connected(self):
        """ Returns the current connection state

        :return: True if an active connection exists,else False.
        :rtype: bool
        """
        return self._is_connected

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
                        self._connected_callback and self._connected_callback(self)
                        self.__receive_thread = threading.Thread(target=self.__receive_thread_worker, name='TCP_Receive')
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
                break
        try:
            self.__connect_threadlock.release()
        except:
            pass

    def _connect(self):
        self.logger.debug("Connecting to {} using {} {} on TCP port {} {} autoreconnect".format(self._host, 'IPv6' if self._ipver == socket.AF_INET6 else 'IPv4', self._hostip, self._port, ('with' if self._autoreconnect else 'without')))
        # Try to connect to remote host using ip (v4 or v6)
        try:
            self._socket = socket.socket(self._ipver, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
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

    def __receive_thread_worker(self):
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
                            self._data_received_callback(self, str.rstrip(str(msg, 'utf-8')))
                    else:
                        # Peer connection closed
                        self.logger.warning("Connection closed by peer {}".format(self._host))
                        self._is_connected = False
                        poller.unregister(self._socket)
                        self._disconnected_callback and self._disconnected_callback(self)
                        if self._autoreconnect:
                            self.logger.debug("Autoreconnect enabled for {}".format(self._host))
                            self.connect()

    def _wait(self, time_lapse):
        time_start = time.time()
        time_end = (time_start + time_lapse)
        while self.__running and time_end > time.time():
            pass

    def close(self):
        self.logger.info("Closing connection to {} on TCP port {}".format(self._host, self._port))
        self.__running = False
        if self.__connect_thread is not None and self.__connect_thread.isAlive():
            self.__connect_thread.join()
        if self.__receive_thread is not None and self.__receive_thread.isAlive():
            self.__receive_thread.join()


class Client(object):
    def __init__(self, socket=None, fd=None):
        self._fd = fd
        self.__socket = socket
        self.__name = None

    @property
    def socket(self):
        return self.__socket

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, name):
        self.__name = name


class tcp_server(object):
    """ Initializes a new instance of tcp_server

    :param interface: Remote interface name or ip address (v4 or v6)
    :param port: Remote interface port to connect to
    :param name: Name of this connection (mainly for logging purposes)
    :param name: Should the socket try to reconnect on lost connection (or finished connect cycle)
    :param connect_retries: Number of connect retries per cycle
    :param connect_cycle: Time between retries inside a connect cycle
    :param retry_cycle: Time between cycles if :param:autoreconnect is True

    :type interface: str
    :type port: int
    :type name: str
    :type name: bool
    :type connect_retries: int
    :type connect_cycle: int
    :type retry_cycle: int
    """

    def __init__(self, port, interface='::', name=None):
        self.logger = logging.getLogger(__name__)

        # Public properties
        self.name = name

        # "Private" properties
        self._interface = interface
        self._port = port
        self._is_listening = False
        self._timeout = 1

        self._interfaceip = None
        self._ipver = socket.AF_INET
        self._socket = None

        self._listening_callback = None
        self._incoming_connection_callback = None
        self._data_received_callback = None

        # "Secret" properties
        self.__listening_thread = None
        self.__listening_threadlock = threading.Lock()
        self.__connection_thread = None
        self.__connection_threadlock = threading.Lock()
        self.__connection_poller = None
        self.__message_queues = {}
        self.__connection_map = {}
        self.__running = True

        # Test if host is an ip address or a host name
        if Network.is_ip(self._interface):
            # host is a valid ip address (v4 or v6)
            self.logger.debug("{} is a valid IP address".format(self._interface))
            self._interfaceip = self._interface
            if Network.is_ipv6(self._interfaceip):
                self._ipver = socket.AF_INET6
            else:
                self._ipver = socket.AF_INET
        else:
            # host is a hostname, trying to resolve to an ip address (v4 or v6)
            self.logger.debug("{} is not a valid IP address, trying to resolve it as hostname".format(self._interface))
            try:
                self._ipver, sockettype, proto, canonname, socketaddr = socket.getaddrinfo(self._interface, None)[0]
                # Check if resolved address is IPv4 or IPv6
                if self._ipver == socket.AF_INET: # is IPv4
                    self._interfaceip, port = socketaddr
                elif self._ipver == socket.AF_INET6: # is IPv6
                    self._interfaceip, port, flow_info, scope_id = socketaddr
                else:
                    # This should never happen
                    self.logger.error("Unknown ip address family {}".format(self._ipver))
                    self._interfaceip = None
                # Print ip address on successfull resolve
                if self._interfaceip is not None:
                    self.logger.info("Resolved {} to {} address {}".format(self._interface, 'IPv6' if self._ipver == socket.AF_INET6 else 'IPv4', self._hostip))
            except:
                # Unable to resolve hostname
                self.logger.error("Cannot resolve {} to a valid ip address (v4 or v6)".format(self._interface))
                self._interfaceip = None

        self.logger.setLevel(logging.DEBUG)
        self.logger.info("Initializing a TCP server socket on interface {} port {}".format(self._interfaceip, self._port))
        
    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, name):
        self.__name = name

    def set_callbacks(self, listening=None, incoming_connection=None, disconnected=None, data_received=None):
        """ Set callbacks to caller for different socket events

        :param connected: Called whenever a connection is established successfully
        :param data_received: Called when data is received
        :param disconnected: Called when a connection has been dropped for whatever reason

        :type connected: function
        :type data_received: function
        :type disconnected: function
        """
        self._listening_callback = listening
        self._incoming_connection_callback = incoming_connection
        self._data_received_callback = data_received
        self._disconnected_callback = disconnected

    def start(self):
        """ Start the server socket

        :return: False if an error prevented us from launching a connection thread. True if a connection thread has been started.
        :rtype: bool
        """
        if self._is_listening:
            return       
        try:
            
            self._socket = socket.socket(self._ipver, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((self._interfaceip, self._port))
        except Exception as e:
            self.logger.error("Problem binding to interface {} on port {}: {}".format(self._interfaceip, self._port, e))
            self._is_listening = False
            return False
        else:
            self.logger.debug("Bound to interface {} on port {}".format(self._interfaceip, self._port))
            #self._poller.register_server(self.socket.fileno(), self)
        
        try:
            self._socket.listen(5)   
            self._socket.setblocking(0)
            self.logger.info("Listening on interface {} port {}".format(self._interfaceip, self._port))
        except Exception as e:
            self.logger.error("Problem starting listening to interface {} on port {}: {}".format(self._interfaceip, self._port, e))
            self._is_listening = False
            return False

        self._is_listening = True
        self._listening_callback and self._listening_callback(self)
        self.__listening_thread = threading.Thread(target=self.__listening_thread_worker, name='TCP_Listener')
        self.__listening_thread.daemon = True
        self.__listening_thread.start()
        return True

    def __listening_thread_worker(self):
        poller = select.poll()
        poller.register(self._socket, select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR)
        self.logger.debug("Waiting for incomming commections on interface {} port {}".format(self._interfaceip, self._port))
        while self.__running:
            events = poller.poll(1000)
            for fd, event in events:
                if event & select.POLLERR:
                    self.logger.debug("Listening thread  POLLERR")
                if event & select.POLLHUP:
                    self.logger.debug("Listening thread  POLLHUP")
                if event & (select.POLLIN | select.POLLPRI):
                    connection, peer = self._socket.accept()
                    connection.setblocking(0)
                    fd = connection.fileno()
                    self.logger.info("Incoming connection from {} on interface {} port {}".format(peer[0], self._interfaceip, self._port))
                    client = Client(socket=connection, fd=fd)
                    client.ip = peer[0]
                    client.ipver = socket.AF_INET6 if Network.is_ipv6(client.ip) else socket.AF_INET
                    client.port = peer[1]
                    if client.ipver == socket.AF_INET6:
                        client.name = '[{}]:{}'.format(client.ip, client.port)
                    else:
                        client.name = '{}:{}'.format(client.ip, client.port)
                    self.__connection_map[fd] = client
                    self.__message_queues[connection] = queue.Queue()
                    self._incoming_connection_callback and self._incoming_connection_callback(self, client)
                    
                    if self.__connection_thread is None:
                        self.logger.debug("Connection thread not running yet, firing it up ...")
                        self.__connection_thread = threading.Thread(target=self.__connection_thread_worker, name='TCP_Server')
                    if self.__connection_poller is None:
                        self.__connection_poller = select.poll()
                    self.__connection_poller.register(connection, select.POLLOUT| select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR)
                    if not self.__connection_thread.isAlive():
                        self.__connection_thread.daemon = True
                        self.__connection_thread.start()
                    
    def __connection_thread_worker(self):
        self.logger.debug("Connection thread on interface {} port {} starting up".format(self._interfaceip, self._port))
        while self.__running and len(self.__connection_map) > 0:
            #self.logger.debug("Connection thread  PING {}".format(len(self.__connection_map)))
            self._wait(1)
            events = self.__connection_poller.poll(1000)
            for fd, event in events:
                if event & select.POLLERR:
                    self.logger.debug("Connection thread  POLLERR")
                if event & select.POLLHUP:
                    self.logger.debug("Connection thread  POLLHUP")
                if event & select.POLLOUT:
                    pass
                if event & (select.POLLIN | select.POLLPRI):
                    __client = self.__connection_map[fd]
                    __socket = __client.socket
                    msg = __socket.recv(4096)
                    if msg:
                        self.logger.debug("Received data from {} {} {} {}".format(__client.name, __client.ip,  'IPv6' if __client.ipver == socket.AF_INET6 else 'IPv4', __client.port))
                        self._data_received_callback and self._data_received_callback(self, __client, str.rstrip(str(msg, 'utf-8')))
                    else:
                        self.logger.info("Connection closed for client {}".format(__client.name))
                        self._disconnected_callback and self._disconnected_callback(self, __socket.getpeername()[0])
                        self.__connection_poller.unregister(fd)
                        del self.__connection_map[fd]
                    del __socket
        self.__connection_poller = None
        self.__connection_thread = None
        self.logger.debug("Last connection closed for interface {} port {}, stopping connection thread".format(self._interfaceip, self._port))
           
    def started(self):
        """ Returns the current connection state

        :return: True if an active connection exists,else False.
        :rtype: bool
        """
        return self._is_started

    def send(self,client,msg):
        if client._fd in self.__connection_map:
            client.socket.send(msg.encode('utf-8'))
        else:
            self.logger.warning("No connection to {}, cannot send data {}".format(client.name, msg))
        

    def _wait(self, time_lapse):
        time_start = time.time()
        time_end = (time_start + time_lapse)
        while self.__running and time_end > time.time():
            pass

    def close(self):
        self.logger.info("Shutting down listening socket on interface {} port {}".format(self._interface, self._port))
        self.__running = False
        if self.__listening_thread is not None and self.__listening_thread.isAlive():
            self.__listening_thread.join()
        #if self.__receive_thread is not None and self.__receive_thread.isAlive():
        #    self.__receive_thread.join()
