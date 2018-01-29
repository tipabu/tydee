import binascii
import unittest

from tydee.message import Message


def get_raw(capture):
    capture = [line for line in capture.split('\n') if line.strip()]
    data_size = int(capture[0].split('(', 1)[1].split(')')[0])
    return b''.join(
        binascii.unhexlify(line[10:49].replace(' ', ''))
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
        req = Message.from_wire(get_raw('''
21:35:59.031985 IP6 2601:645:4101:29a0:14f5:2523:cb60:3279.52787 > cdns01.comcast.net.domain: 45959+ [1au] A? www.swiftstack.com. (47)
	0x0000:  e8fc afa6 7c44 881f a127 73b4 86dd 600d  ....|D...'s...`.
	0x0010:  8475 0037 1140 2601 0645 4101 29a0 14f5  .u.7.@&..EA.)...
	0x0020:  2523 cb60 3279 2001 0558 feed 0000 0000  %#.`2y...X......
	0x0030:  0000 0000 0001 ce33 0035 0037 ecaf b387  .......3.5.7....
	0x0040:  0120 0001 0000 0000 0001 0377 7777 0a73  ...........www.s
	0x0050:  7769 6674 7374 6163 6b03 636f 6d00 0001  wiftstack.com...
	0x0060:  0001 0000 2910 0000 0000 0000 00         ....)........
        '''))
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
        req = Message.from_wire(get_raw(r'''
21:36:18.122359 IP6 2601:645:4101:29a0:14f5:2523:cb60:3279.52788 > cdns01.comcast.net.domain: 58409+ [1au] A? google.com. (39)
	0x0000:  e8fc afa6 7c44 881f a127 73b4 86dd 6003  ....|D...'s...`.
	0x0010:  5a45 002f 1140 2601 0645 4101 29a0 14f5  ZE./.@&..EA.)...
	0x0020:  2523 cb60 3279 2001 0558 feed 0000 0000  %#.`2y...X......
	0x0030:  0000 0000 0001 ce34 0035 002f 1cf1 e429  .......4.5./...)
	0x0040:  0120 0001 0000 0000 0001 0667 6f6f 676c  ...........googl
	0x0050:  6503 636f 6d00 0001 0001 0000 2910 0000  e.com.......)...
	0x0060:  0000 0000 00                             .....
        '''))
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
        req = Message.from_wire(get_raw(r'''
21:35:45.729738 IP6 2601:645:4101:29a0:14f5:2523:cb60:3279.53748 > cdns01.comcast.net.domain: 2175+ AAAA? googlemail.l.google.com. (41)
	0x0000:  e8fc afa6 7c44 881f a127 73b4 86dd 6000  ....|D...'s...`.
	0x0010:  9969 0031 11ff 2601 0645 4101 29a0 14f5  .i.1..&..EA.)...
	0x0020:  2523 cb60 3279 2001 0558 feed 0000 0000  %#.`2y...X......
	0x0030:  0000 0000 0001 d1f4 0035 0031 dd92 087f  .........5.1....
	0x0040:  0100 0001 0000 0000 0000 0a67 6f6f 676c  ...........googl
	0x0050:  656d 6169 6c01 6c06 676f 6f67 6c65 0363  email.l.google.c
	0x0060:  6f6d 0000 1c00 01                        om.....
        '''))
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
        resp = Message.from_wire(get_raw(r'''
21:35:59.475771 IP6 cdns01.comcast.net.domain > 2601:645:4101:29a0:14f5:2523:cb60:3279.52787: 45959 2/0/1 CNAME swiftstack.com., A 166.78.179.120 (77)
	0x0000:  881f a127 73b4 e8fc afa6 7c44 86dd 6000  ...'s.....|D..`.
	0x0010:  0000 0055 113a 2001 0558 feed 0000 0000  ...U.:...X......
	0x0020:  0000 0000 0001 2601 0645 4101 29a0 14f5  ......&..EA.)...
	0x0030:  2523 cb60 3279 0035 ce33 0055 cfc3 b387  %#.`2y.5.3.U....
	0x0040:  8180 0001 0002 0000 0001 0377 7777 0a73  ...........www.s
	0x0050:  7769 6674 7374 6163 6b03 636f 6d00 0001  wiftstack.com...
	0x0060:  0001 c00c 0005 0001 0000 012c 0002 c010  ...........,....
	0x0070:  c010 0001 0001 0000 012c 0004 a64e b378  .........,...N.x
	0x0080:  0000 2902 0000 0000 0000 00              ..)........
'''))
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
        resp = Message.from_wire(get_raw(r'''
21:36:18.137272 IP6 cdns01.comcast.net.domain > 2601:645:4101:29a0:14f5:2523:cb60:3279.52788: 58409 1/0/1 A 216.58.195.238 (55)
	0x0000:  881f a127 73b4 e8fc afa6 7c44 86dd 6000  ...'s.....|D..`.
	0x0010:  0000 003f 113a 2001 0558 feed 0000 0000  ...?.:...X......
	0x0020:  0000 0000 0001 2601 0645 4101 29a0 14f5  ......&..EA.)...
	0x0030:  2523 cb60 3279 0035 ce34 003f 3f46 e429  %#.`2y.5.4.??F.)
	0x0040:  8180 0001 0001 0000 0001 0667 6f6f 676c  ...........googl
	0x0050:  6503 636f 6d00 0001 0001 c00c 0001 0001  e.com...........
	0x0060:  0000 00fb 0004 d83a c3ee 0000 2902 0000  .......:....)...
	0x0070:  0000 0000 00                             .....
'''))
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
        resp = Message.from_wire(get_raw(r'''
21:35:45.743767 IP6 cdns01.comcast.net.domain > 2601:645:4101:29a0:14f5:2523:cb60:3279.53748: 2175 1/0/0 AAAA 2607:f8b0:4005:808::2005 (69)
	0x0000:  881f a127 73b4 e8fc afa6 7c44 86dd 6000  ...'s.....|D..`.
	0x0010:  0000 004d 113a 2001 0558 feed 0000 0000  ...M.:...X......
	0x0020:  0000 0000 0001 2601 0645 4101 29a0 14f5  ......&..EA.)...
	0x0030:  2523 cb60 3279 0035 d1f4 004d 4891 087f  %#.`2y.5...MH...
	0x0040:  8180 0001 0001 0000 0000 0a67 6f6f 676c  ...........googl
	0x0050:  656d 6169 6c01 6c06 676f 6f67 6c65 0363  email.l.google.c
	0x0060:  6f6d 0000 1c00 01c0 0c00 1c00 0100 0001  om..............
	0x0070:  1000 1026 07f8 b040 0508 0800 0000 0000  ...&...@........
	0x0080:  0020 05                                  ...
'''))
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
