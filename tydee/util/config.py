import logging
import socket
import string
from typing import Any, Dict, List, Sequence, Tuple, Union

from ..message import ResourceRecord, Domain


LOGGER = logging.getLogger('tydee.util.config')


def valid_domain_name(name : Union[str, bytes, Sequence[str]], allow_wildcard : bool = True) -> bool:
    ld = string.ascii_letters + string.digits
    ldh = ld + '-'
    if isinstance(name, bytes):
        try:
            name = name.decode('ascii')
        except UnicodeDecodeError:
            return False
    if isinstance(name, str):
        name = name.split('.')
    if allow_wildcard and name and name[0] == '*':
        name = name[1:]
    return all(
        label and all(c in ldh for c in label) and
        label[0] in string.ascii_letters and label[-1] in ld
        for label in name)


def load_cname_records(parser) -> List[Tuple[str, Domain]]:
    records : List[Tuple[str, Domain]] = []
    if not parser.has_section('cname'):
        return records
    for name, cname in parser.items('cname'):
        if not valid_domain_name(name):
            raise ValueError('invalid domain name %r' % name)
        if not valid_domain_name(cname, allow_wildcard=False):
            raise ValueError('invalid canonical name %r' % cname)
        records.append((name, Domain(cname)))
    return records


def load_a_records(parser) -> List[Tuple[str, str]]:
    records : List[Tuple[str, str]] = []
    if not parser.has_section('ipv4'):
        return records
    for name, addrs in parser.items('ipv4'):
        if not valid_domain_name(name):
            raise ValueError('invalid domain name %r' % name)
        for addr in addrs.strip().split('\n'):
            try:
                socket.inet_pton(socket.AF_INET, addr)
            except socket.error:
                raise ValueError('invalid IPv4 address %r' % addr)
            records.append((name, addr))
    return records


def load_aaaa_records(parser) -> List[Tuple[str, str]]:
    records : List[Tuple[str, str]] = []
    if not parser.has_section('ipv6'):
        return records
    for name, addrs in parser.items('ipv6'):
        if not valid_domain_name(name):
            raise ValueError('invalid domain name %r' % name)
        for addr in addrs.strip().split('\n'):
            try:
                socket.inet_pton(socket.AF_INET6, addr)
            except socket.error:
                raise ValueError('invalid IPv6 address %r' % addr)
            records.append((name, addr))
    return records


def load_txt_records(parser) -> List[Tuple[str, Tuple[str]]]:
    records : List[Tuple[str, Tuple[str]]] = []
    if not parser.has_section('txt'):
        return records
    for name, txt in parser.items('txt'):
        if not valid_domain_name(name):
            raise ValueError('invalid domain name %r' % name)
        if not isinstance(txt, bytes):
            txt = txt.encode('latin1')
        records.extend((name, (x,)) for x in txt.strip().split(b'\n'))
    return records


class RRDB(object):
    def __init__(self, data : dict = None):
        self.tree : Dict[str, Any] = {}
        if data:
            for rr_type, entries in data.items():
                for name, data in entries:
                    t = self.tree
                    for label in reversed(name.split('.')):
                        t = t.setdefault(label, {})
                    # TODO: maybe make these proper ResourceRecords?
                    t.setdefault('.', []).append((rr_type, data))

    def lookup(self, name : Domain) -> Union[Tuple[ResourceRecord, ...], None]:
        t = self.tree
        wildcard = t.get('*')
        for label in reversed(name):
            if '*' in t:
                wildcard = t['*']
            if label not in t:
                break
            t = t[label]
        else:  # found node
            if '.' not in t:  # have records *under* it, but nothing *here*
                return ()
            else:  # exact match
                return tuple(
                    ResourceRecord(name, rrtype, 'IN', 300, data)
                    for rrtype, data in t['.'])
        if wildcard:
            return tuple(
                ResourceRecord(name, rrtype, 'IN', 300, data)
                for rrtype, data in wildcard['.'])
        else:
            return None

    @classmethod
    def from_parser(cls, parser) -> RRDB:
        new_db = {
            'CNAME': load_cname_records(parser),
            'A': load_a_records(parser),
            'AAAA': load_aaaa_records(parser),
            'TXT': load_txt_records(parser),
        }
        LOGGER.debug('Loaded db %r', new_db)
        return cls(new_db)
