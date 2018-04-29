import os
import threading
import unittest

import tydee.server


class BaseTestWithServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        conf_file = os.path.join(os.path.dirname(__file__), 'dns.conf')
        cls.server = tydee.server.Server(conf_file)
        cls.server_thread = threading.Thread(target=cls.server.run)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        # Give the server a chance to start
        if not cls.server.bound_event.wait(0.1):
            raise cls.failureException('Server failed to start')

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server_thread.join()

    def setUp(self):
        if not self.server_thread.is_alive():
            self.fail('Server is not running.')
