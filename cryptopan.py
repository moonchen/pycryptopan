#   pycryptopan - a python module implementing the CryptoPAn algorithm
#   Copyright (C) 2013 - the CONFINE project

#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Lesser General Public License as
#   published by the Free Software Foundation, either version 3 of the
#   License, or (at your option) any later version.

#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.

#   You should have received a copy of the GNU Lesser General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

from functools import reduce
from Crypto.Cipher.AES import new as AES
from netaddr import IPAddress

class CryptoPanError(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class CryptoPan():

    def __init__(self, key):
        if len(key) != 32:
            raise CryptoPanError("Key must be a 32 byte long string")
        self.aes = AES(key[0:16])
        self.pad = self.aes.encrypt(key[16:32])

        pad_int = sum(ord(c) << (i * 8) for i, c in enumerate(self.pad[::-1]))

        self.masks = [(mask, pad_int & (~ mask))
                      for mask in ((2 ** 128 - 1) >> (128 - p) << (128 - p) for p in range(0, 128))]

    def pack(self, val, num_bytes):
        return "".join([chr(val >> i * 8 & 0xff) for i in xrange(num_bytes - 1, -1, -1)])

    def anonymize(self, ip_in):
        ip = IPAddress(ip_in)

        if ip.version == 4:
            address_bytes = 4
            address = ip.value << (128 - 32)
        else:
            address_bytes = 16
            address = ip.value

        def calc(a):
            """ calculate the first bit for Crypto-PAN"""
            # a is a number, convert to a string
            rin_input = self.pack(a, 16)
            rin_output = self.aes.encrypt(rin_input)
            out = rin_output[0]
            return ord(out) >> 7

        addresses = ((address & mask[0]) | mask[1] for mask in self.masks[0:address_bytes * 8])
        result = reduce(
            lambda x, y: x << 1 | y,
            (calc(a) for a in addresses),
            0)

        return IPAddress(result ^ ip.value)


if __name__ == "__main__":
    import time
    c = CryptoPan("".join((chr(x) for x in range(0, 32))))
    print("expected: 2.90.93.17")
    print("calculated: " + str(c.anonymize("192.0.2.1")))
    print("expected: dd92:2c44:3fc0:ff1e:7ff9:ff:787c:8c58")
    print("calculated: " + str(c.anonymize("2001:db8::ff00:42:8329")))
    print("starting performance check")
    stime = time.time()
    for i in range(0, 1000):
        c.anonymize("192.0.2.1")
    dtime = time.time() - stime
    print("1000 anonymizations in %s s" % dtime)
