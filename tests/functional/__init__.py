import os
import threading
import unittest

import tydee.server


class BaseTestWithServer(unittest.TestCase):
    @classmethod
    def get_server_address(cls):
        if ':' in cls.server.bind_ip:
            if tydee.server.IPv6Address(cls.server.bind_ip) == \
                    tydee.server.IPv6Address('::'):
                return '::1'
        else:
            if tydee.server.IPv4Address(cls.server.bind_ip) == \
                    tydee.server.IPv4Address('0.0.0.0'):
                return '127.0.0.1'
        return cls.server.bind_ip

    @classmethod
    def setUpClass(cls):
        conf_file = os.path.join(os.path.dirname(__file__), 'dns.conf')
        cls.server = tydee.server.UDPServer(conf_file)
        cls.check_can_run()
        cls.server_thread = threading.Thread(target=cls.server.run)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        # Give the server a chance to start
        if not cls.server.running_event.wait(0.1):
            raise cls.failureException('Server failed to start')

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server_thread.join()

    @classmethod
    def check_can_run(cls):
        '''
        Hook to allow a test class to abort before the server even starts.

        Config will have been loaded, ``cls.server`` will be defined; you
        may want to do something like raise ``unittest.SkipTest`` or
        ``cls.failureException`` here.
        '''
        pass

    def setUp(self):
        if not self.server_thread.is_alive():
            self.fail('Server is not running.')
