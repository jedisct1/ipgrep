#! /usr/bin/env python

import csv
import fileinput
import GeoIP
import pycares
import re
import select
import sys

GEOIPASNUM_FILE_DEFAULT = "/opt/geoip/GeoIPASNum.dat"


class GeoLookup(object):
    def __init__(self, path=GEOIPASNUM_FILE_DEFAULT):
        self.geoip = GeoIP.open(path, GeoIP.GEOIP_STANDARD)

    def asn(self, ip):
        asn = self.geoip.name_by_addr(ip)
        if asn is None:
            return None
        asn_number = re.sub(r"^AS(\d+).+", "\\1", asn)
        try:
            asn_number = int(asn_number)
        except ValueError:
            return None
        return ASN(number=asn_number, full=asn)


class ASN(object):
    def __init__(self, number, full):
        self.number = number
        self.full = full


class Host(object):
    def __init__(self, ip=None, name=None, asn=None):
        self.ip = ip
        self.name = name
        self.asn = asn

    def __repr__(self):
        return "ip: {}\t name: {} ASN: {}".format(self.ip, self.name,
                                                  self.asn.full)


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
        self.channel = pycares.Channel(timeout=1.0, tries=1)

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
        matches = re.findall(r"(" + label_r +
                             r"(" + label_r + "){,8}" +
                             label_last + r")[.]?",
                             self.txt, re.I)
        names = [re.sub(r",", ".", x[0]).lower() for x in matches]
        names = [re.sub(r"[^a-z0-9-.]", "", x) for x in names]
        return names

    def extract_ips(self):
        matches = re.findall(r"([^0-9]|^)([1-9][0-9]{0,2}(\.|\s*\[\.?\]\s*)" +
                             "[[1-9][0-9]{0,2}(\.|\s*\[\.?\]\s*)" +
                             "[1-9][0-9]{0,2}(\.|\s*\[\.?\]\s*)" +
                             "[1-9][0-9]{0,2})([^0-9]|$)", self.txt)
        ips = [re.sub(r"[^0-9.]", "", x[1]) for x in matches]
        return ips


if __name__ == "__main__":
    geo = GeoLookup()
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
        asn = geo.asn(host.ip)
        if not asn:
            asn = ASN(0, "-")
        host.asn = asn
        if not host.name:
            host.name = "-"

    for host in sorted(hosts, key=lambda x: (x.asn.full, x.ip, x.name)):
        csvw.writerow([host.ip, host.name, host.asn.full])
