#! /usr/bin/env python3

import csv
import fileinput
import json
import pycares
import re
import requests
import select
import socket
import sys

IPTOASN_BASE_ENDPOINT_URL = "https://api.iptoasn.com/v1/as/ip/"


class IPLookup(object):
    def lookup(self, ip):
        url = IPTOASN_BASE_ENDPOINT_URL + ip
        r = requests.get(url)
        if r.status_code != 200:
            return None
        info = r.json()
        if info is None or info['announced'] is False:
            return None
        return info


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
            asn = ASN(subnet['as_number'], subnet['as_country_code'],
                      "AS{}: {} ({})".format(subnet['as_number'],
                                             subnet['as_description'],
                                             subnet['as_country_code']))
        if not host.name:
            host.name = "-"
        host.asn = asn

    for host in sorted(hosts, key=lambda x: (x.asn.description, x.ip, x.name)):
        csvw.writerow([host.ip, host.name, host.asn.description])
