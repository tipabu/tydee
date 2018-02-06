import binascii
import os
import unittest

from tydee.message import Message


def get_raw(name):
    name = os.path.join(os.path.dirname(__file__), 'captures', name)
    with open(name, 'rb') as fp:
        capture = [line for line in fp if line.strip()]
    data_size = int(capture[0].split(b'(', 1)[1].split(b')')[0])
    return b''.join(
        binascii.unhexlify(line[10:49].replace(b' ', b''))
        for line in capture[1:])[-data_size:]


class TestMessage(unittest.TestCase):
    maxDiff = None

    def assertLength(self, arr, length):
        self.assertEqual(
            len(arr), length,
            'len(%r) == %d, not %d as expected' % (arr, len(arr), length))

    # Captured with something like:
    #    sudo tcpdump -X udp port 53
    def test_request_parsing_1(self):
        req = Message.from_wire(get_raw('req1.dump'))
        self.assertFalse(req.is_response)
        self.assertEqual(req.op_code_name, 'Query')
        self.assertFalse(req.is_authoritative)
        self.assertFalse(req.is_truncated)
        self.assertTrue(req.recursion_desired)
        self.assertFalse(req.recursion_available)
        self.assertEqual(req.reserved, 0)
        self.assertTrue(req.authentic_data)
        self.assertFalse(req.checking_disabled)
        self.assertEqual(req.response_code_name, 'NoError')
        self.assertLength(req.questions, 1)
        self.assertEqual(str(req.questions[0].name), 'www.swiftstack.com')
        self.assertEqual(req.questions[0].qtype_name, 'A')
        self.assertEqual(req.questions[0].qclass_name, 'IN')
        self.assertLength(req.answers, 0)
        self.assertLength(req.name_servers, 0)
        self.assertLength(req.additional_records, 1)
        self.assertEqual(str(req.additional_records[0].rrname), '')
        self.assertEqual(req.additional_records[0].rrtype_name, 'OPT')
        self.assertEqual(req.additional_records[0].rrclass, 4096)
        self.assertEqual(req.additional_records[0].ttl, 0)
        self.assertEqual(req.additional_records[0].data, b'')
        self.assertEqual(req.to_wire(), req.raw_data)

    def test_request_parsing_2(self):
        req = Message.from_wire(get_raw('req2.dump'))
        self.assertFalse(req.is_response)
        self.assertEqual(req.op_code_name, 'Query')
        self.assertFalse(req.is_authoritative)
        self.assertFalse(req.is_truncated)
        self.assertTrue(req.recursion_desired)
        self.assertFalse(req.recursion_available)
        self.assertEqual(req.reserved, 0)
        self.assertTrue(req.authentic_data)
        self.assertFalse(req.checking_disabled)
        self.assertEqual(req.response_code_name, 'NoError')
        self.assertLength(req.questions, 1)
        self.assertEqual(str(req.questions[0].name), 'google.com')
        self.assertEqual(req.questions[0].qtype_name, 'A')
        self.assertEqual(req.questions[0].qclass_name, 'IN')
        self.assertLength(req.answers, 0)
        self.assertLength(req.name_servers, 0)
        self.assertLength(req.additional_records, 1)
        self.assertEqual(str(req.additional_records[0].rrname), '')
        self.assertEqual(req.additional_records[0].rrtype_name, 'OPT')
        self.assertEqual(req.additional_records[0].rrclass, 4096)
        self.assertEqual(req.additional_records[0].ttl, 0)
        self.assertEqual(req.additional_records[0].data, b'')
        self.assertEqual(req.to_wire(), req.raw_data)

    def test_request_parsing_3(self):
        req = Message.from_wire(get_raw('req3.dump'))
        self.assertFalse(req.is_response)
        self.assertEqual(req.op_code_name, 'Query')
        self.assertFalse(req.is_authoritative)
        self.assertFalse(req.is_truncated)
        self.assertTrue(req.recursion_desired)
        self.assertFalse(req.recursion_available)
        self.assertEqual(req.reserved, 0)
        self.assertFalse(req.authentic_data)
        self.assertFalse(req.checking_disabled)
        self.assertEqual(req.response_code_name, 'NoError')
        self.assertLength(req.questions, 1)
        self.assertEqual(str(req.questions[0].name), 'googlemail.l.google.com')
        self.assertEqual(req.questions[0].qtype_name, 'AAAA')
        self.assertEqual(req.questions[0].qclass_name, 'IN')
        self.assertLength(req.answers, 0)
        self.assertLength(req.name_servers, 0)
        self.assertLength(req.additional_records, 0)
        self.assertEqual(req.to_wire(), req.raw_data)

    def test_response_parsing_1(self):
        resp = Message.from_wire(get_raw('resp1.dump'))
        self.assertTrue(resp.is_response)
        self.assertEqual(resp.op_code_name, 'Query')
        self.assertFalse(resp.is_authoritative)
        self.assertFalse(resp.is_truncated)
        self.assertTrue(resp.recursion_desired)
        self.assertTrue(resp.recursion_available)
        self.assertEqual(resp.reserved, 0)
        self.assertFalse(resp.authentic_data)
        self.assertFalse(resp.checking_disabled)
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertLength(resp.questions, 1)
        self.assertEqual(str(resp.questions[0].name), 'www.swiftstack.com')
        self.assertEqual(resp.questions[0].qtype_name, 'A')
        self.assertEqual(resp.questions[0].qclass_name, 'IN')
        self.assertLength(resp.answers, 2)
        self.assertEqual(str(resp.answers[0].rrname), 'www.swiftstack.com')
        self.assertEqual(resp.answers[0].rrtype_name, 'CNAME')
        self.assertEqual(resp.answers[0].rrclass_name, 'IN')
        self.assertEqual(resp.answers[0].ttl, 300)
        self.assertEqual(str(resp.answers[0].data), 'swiftstack.com')
        self.assertEqual(str(resp.answers[1].rrname), 'swiftstack.com')
        self.assertEqual(resp.answers[1].rrtype_name, 'A')
        self.assertEqual(resp.answers[1].rrclass_name, 'IN')
        self.assertEqual(resp.answers[1].ttl, 300)
        self.assertEqual(resp.answers[1].data, '166.78.179.120')
        self.assertLength(resp.name_servers, 0)
        self.assertLength(resp.additional_records, 1)
        self.assertEqual(str(resp.additional_records[0].rrname), '')
        self.assertEqual(resp.additional_records[0].rrtype_name, 'OPT')
        self.assertEqual(resp.additional_records[0].rrclass, 512)
        self.assertEqual(resp.additional_records[0].ttl, 0)
        self.assertEqual(resp.additional_records[0].data, b'')
        self.assertEqual(Message.from_wire(resp.to_wire())[1:], resp[1:])
        # TODO: need reasonably efficient compression for
        # self.assertEqual(resp.to_wire(), resp.raw_data)

    def test_response_parsing_2(self):
        resp = Message.from_wire(get_raw('resp2.dump'))
        self.assertTrue(resp.is_response)
        self.assertEqual(resp.op_code_name, 'Query')
        self.assertFalse(resp.is_authoritative)
        self.assertFalse(resp.is_truncated)
        self.assertTrue(resp.recursion_desired)
        self.assertTrue(resp.recursion_available)
        self.assertEqual(resp.reserved, 0)
        self.assertFalse(resp.authentic_data)
        self.assertFalse(resp.checking_disabled)
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertLength(resp.questions, 1)
        self.assertEqual(str(resp.questions[0].name), 'google.com')
        self.assertEqual(resp.questions[0].qtype_name, 'A')
        self.assertEqual(resp.questions[0].qclass_name, 'IN')
        self.assertLength(resp.answers, 1)
        self.assertEqual(str(resp.answers[0].rrname), 'google.com')
        self.assertEqual(resp.answers[0].rrtype_name, 'A')
        self.assertEqual(resp.answers[0].rrclass_name, 'IN')
        self.assertEqual(resp.answers[0].ttl, 251)
        self.assertEqual(resp.answers[0].data, '216.58.195.238')
        self.assertLength(resp.name_servers, 0)
        self.assertLength(resp.additional_records, 1)
        self.assertEqual(str(resp.additional_records[0].rrname), '')
        self.assertEqual(resp.additional_records[0].rrtype_name, 'OPT')
        self.assertEqual(resp.additional_records[0].rrclass, 512)
        self.assertEqual(resp.additional_records[0].ttl, 0)
        self.assertEqual(resp.additional_records[0].data, b'')
        self.assertEqual(Message.from_wire(resp.to_wire())[1:], resp[1:])
        # TODO: need reasonably efficient compression for
        # self.assertEqual(resp.to_wire(), resp.raw_data)

    def test_response_parsing_3(self):
        resp = Message.from_wire(get_raw('resp3.dump'))
        self.assertTrue(resp.is_response)
        self.assertEqual(resp.op_code_name, 'Query')
        self.assertFalse(resp.is_authoritative)
        self.assertFalse(resp.is_truncated)
        self.assertTrue(resp.recursion_desired)
        self.assertTrue(resp.recursion_available)
        self.assertEqual(resp.reserved, 0)
        self.assertFalse(resp.authentic_data)
        self.assertFalse(resp.checking_disabled)
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertLength(resp.questions, 1)
        self.assertEqual(str(resp.questions[0].name),
                         'googlemail.l.google.com')
        self.assertEqual(resp.questions[0].qtype_name, 'AAAA')
        self.assertEqual(resp.questions[0].qclass_name, 'IN')
        self.assertLength(resp.answers, 1)
        self.assertEqual(str(resp.answers[0].rrname),
                         'googlemail.l.google.com')
        self.assertEqual(resp.answers[0].rrtype_name, 'AAAA')
        self.assertEqual(resp.answers[0].rrclass_name, 'IN')
        self.assertEqual(resp.answers[0].ttl, 272)
        self.assertEqual(resp.answers[0].data, '2607:f8b0:4005:808::2005')

        self.assertLength(resp.name_servers, 0)
        self.assertLength(resp.additional_records, 0)
        self.assertEqual(Message.from_wire(resp.to_wire())[1:], resp[1:])
        # TODO: need reasonably efficient compression for
        # self.assertEqual(resp.to_wire(), resp.raw_data)
