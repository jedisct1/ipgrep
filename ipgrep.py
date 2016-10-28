#! /usr/bin/env python

import csv
import fileinput
import pycares
import re
import select
import sortedcontainers
import socket
import sys

IP2ASN_FILE_DEFAULT = "/opt/ip2asn/ip2asn-v4-u32.tsv"


class IPLookup(object):
    class Subnet(object):
        def __init__(self, first_ip, last_ip, asn, country_code, description):
            self.first_ip = long(first_ip)
            self.last_ip = long(last_ip)
            self.asn = int(asn)
            self.country_code = country_code
            self.description = description

        def none(self):
            return Subnet(0, 0, 0, "-", "-")

    def __init__(self, path=IP2ASN_FILE_DEFAULT):
        self.subnets = sortedcontainers.SortedDict()
        with open(path) as f:
            for line in f:
                parts = str.split(str.strip(line), "\t")
                if len(parts) < 5:
                    parts.append("-")
                subnet = IPLookup.Subnet(parts[0], parts[1], parts[2],
                                         parts[3], parts[4])
                self.subnets[subnet.first_ip] = subnet

    def lookup(self, ip):
        try:
            ip4 = socket.inet_aton(ip)
        except socket.error:
            return None
        ipn = (ord(ip4[0]) << 24) | (ord(ip4[1]) << 16) | \
              (ord(ip4[2]) << 8) | (ord(ip4[3]))
        found = None
        try:
            found_key = self.subnets.irange(minimum=None, maximum=ipn,
                                            inclusive=(True, True),
                                            reverse=True).next()
        except StopIteration:
            return None
        found = self.subnets[found_key]
        if found.last_ip < ipn:
            return None
        return found


class ASN(object):
    def __init__(self, number, country_code, description):
        self.number = number
        self.description = description


class Host(object):
    def __init__(self, ip=None, name=None, asn=None):
        self.ip = ip
        self.name = name
        self.asn = asn

    def __repr__(self):
        return "ip: {}\t name: {} ASN: {}".format(
            self.ip, self.name, self.asn.description)


class ResolverResponse(object):
    def __init__(self, name, channel, res):
        def cb(results, err):
            if results is None:
                return
            for result in results:
                res.add((result.host, self.name))

        self.name = name
        channel.query(name, pycares.QUERY_TYPE_A, cb)


class Resolver(object):
    def __init__(self):
        self.channel = pycares.Channel(timeout=5.0, tries=2)

    def _wait(self):
        while True:
            read_fds, write_fds = self.channel.getsock()
            if not read_fds and not write_fds:
                break
            timeout = self.channel.timeout()
            if timeout == 0.0:
                self.channel.process_fd(pycares.ARES_SOCKET_BAD,
                                        pycares.ARES_SOCKET_BAD)
                continue
            rlist, wlist, xlist = select.select(read_fds, write_fds, [],
                                                timeout)
            for fd in rlist:
                self.channel.process_fd(fd, pycares.ARES_SOCKET_BAD)
            for fd in wlist:
                self.channel.process_fd(pycares.ARES_SOCKET_BAD, fd)

    def resolve(self, names):
        res = set()
        for name in names:
            response = ResolverResponse(name, self.channel, res)
        self._wait()
        return res


class Extractor(object):
    def __init__(self, txt):
        self.txt = txt

    def extract_names(self):
        label_r = r"[a-z0-9-]{1,63}([.]|\\[.]|,|\[[.]\]|[.]\]| [.])"
        label_last = r"[a-z0-9]{1,16}($|[^a-z0-9])"
        matches = re.findall(r"(" +
                             r"(" + label_r + "){1,8}" +
                             label_last + r")[.]?",
                             self.txt, re.I)
        names = [re.sub(r",", ".", x[0]).lower() for x in matches]
        names = [re.sub(r"[^a-z0-9-.]", "", x) for x in names]
        return names

    def extract_ips(self):
        matches = re.findall(r"([^0-9]|^)([0-9]{1,3}(\.|\s*\[\.?\]\s*)" +
                             "[0-9]{1,3}(\.|\s*\[\.?\]\s*)" +
                             "[0-9]{1,3}(\.|\s*\[\.?\]\s*)" +
                             "[0-9]{1,3})([^0-9]|$)", self.txt)
        ips = [re.sub(r"[^0-9.]", "", x[1]) for x in matches]
        return ips


if __name__ == "__main__":
    ip_lookup = IPLookup()
    resolver = Resolver()
    csvw = csv.writer(sys.stdout, delimiter="\t")
    names, ips = set(), set()

    for line in fileinput.input():
        extractor = Extractor(line)
        names = names | set(extractor.extract_names())
        ips = ips | set(extractor.extract_ips())

    resolved = resolver.resolve(names)
    hosts_fromnames = set([Host(ip=ip, name=name) for ip, name in resolved])
    hosts_fromips = set([Host(ip=ip) for ip in ips])
    hosts = hosts_fromnames | hosts_fromips

    for host in hosts:
        subnet = ip_lookup.lookup(host.ip)
        asn = ASN(0, "-", "-")
        if subnet:
            asn = ASN(subnet.asn, subnet.country_code,
                      "AS{}: {} ({})".format(subnet.asn, subnet.description,
                                             subnet.country_code))
        if not host.name:
            host.name = "-"
        host.asn = asn

    for host in sorted(hosts, key=lambda x: (x.asn.description, x.ip, x.name)):
        csvw.writerow([host.ip, host.name, host.asn.description])
