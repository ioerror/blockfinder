#!/usr/bin/python
import blockfinder
import unittest
import os

class CheckReverseLookup(unittest.TestCase):

    ipValues = ( (3229318011, '192.123.123.123'),
                    (3463778365, '206.117.16.61'),
                    (4278190202, '255.0.0.122'),
                  (3654084623, '217.204.232.15'),
                  (134217728, '8.0.0.0'))

    rirValues = ( ('217.204.232.15', 'GB'),
                  ('188.72.225.100', 'DE'),
                  ('8.8.8.1', 'US'))

    cache_dir = str(os.path.expanduser('~')) + "/.blockfinder/"

    def test_rir_lookup(self):
        for ip, cc in self.rirValues:
            result = blockfinder.rir_lookup(ip, self.cache_dir)
            self.assertEqual(result[0], cc)

    def test_ip_address_to_dec(self):
        for dec, ip in self.ipValues:
            result = blockfinder.ip_address_to_dec(ip)
            self.assertEqual(result, dec)

class CheckBlockFinder(unittest.TestCase):
    cache_dir = str(os.path.expanduser('~')) + "/.blockfinder/"


    # You can add known blocks to the tuple as a list
    # they will be looked up and checked
    knownResults = ( ('mm', ['203.81.64.0/19',
                            '203.81.160.0/20']),
                    ('kp', ['175.45.176.0/22']))

    def test_ipv4_bf(self):
        blockfinder.verbose = 0
        for cc, values in self.knownResults:
            self.result = blockfinder.use_sql_database("ipv4", cc.upper(), self.cache_dir)
            self.assertEqual(self.result, values)


class CheckBasicFunctionOperation(unittest.TestCase):
    def test_calc_ipv4_subnet_boundary(self):
        for i in range(0, 29):
            host_count = 2 ** i
            subnet = 32 - i
            self.assertEqual(blockfinder.calculate_ipv4_subnet(host_count), subnet)

    def test_calc_ipv4_subnet_not_on_boundary(self):
            self.assertEqual(blockfinder.calculate_ipv4_subnet(254), 24)
            self.assertEqual(blockfinder.calculate_ipv4_subnet(255), 24)
            self.assertEqual(blockfinder.calculate_ipv4_subnet(257), 23)
            self.assertEqual(blockfinder.calculate_ipv4_subnet(259), 23)


if __name__ == '__main__':
    unittest.main()

