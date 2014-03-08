#!/usr/bin/python
import unittest
import os
import shutil
import sys
import tempfile

import blockfinder
from blockfinder import ipaddr


class BaseBlockfinderTest(unittest.TestCase):
    def setUp(self):
        self.base_test_dir = tempfile.mkdtemp()
        self.test_dir = self.base_test_dir + "/test/"
        self.database_cache = blockfinder.DatabaseCache(self.test_dir)
        self.downloader_parser = blockfinder.DownloaderParser(
                self.test_dir, self.database_cache, "Mozilla")
        self.lookup = blockfinder.Lookup(self.test_dir, self.database_cache)
        self.database_cache.connect_to_database()
        self.database_cache.set_db_version()
        shutil.copy('test_rir_data', self.test_dir + 'test_rir_data')
        shutil.copy('test_lir_data.gz', self.test_dir + 'test_lir_data.gz')
        self.downloader_parser.parse_rir_files(['test_rir_data'])
        self.downloader_parser.parse_lir_files(['test_lir_data.gz'])

    def tearDown(self):
        shutil.rmtree(self.base_test_dir, True)


class CheckReverseLookup(BaseBlockfinderTest):
    def test_rir_ipv4_lookup(self):
        self.assertEqual(self.database_cache.fetch_country_code('ipv4',
                'rir', int(ipaddr.IPv4Address('175.45.176.100'))), 'KP')
        self.assertEqual(self.database_cache.fetch_country_code('ipv4',
                'rir', int(ipaddr.IPv4Address('193.9.26.0'))), 'HU')
        self.assertEqual(self.database_cache.fetch_country_code('ipv4',
                'rir', int(ipaddr.IPv4Address('193.9.25.1'))), 'PL')
        self.assertEqual(self.database_cache.fetch_country_code('ipv4',
                'rir', int(ipaddr.IPv4Address('193.9.25.255'))), 'PL')

    def test_rir_asn_lookup(self):
        self.assertEqual(self.database_cache.fetch_country_code('asn',
                'rir', 681), 'NZ')
        self.assertEqual(self.database_cache.fetch_country_code('asn',
                'rir', 173), 'JP')

    def test_lir_ipv4_lookup(self):
        self.assertEqual(self.database_cache.fetch_country_code('ipv4',
                'lir', int(ipaddr.IPv4Address('80.16.151.184'))), 'IT')
        self.assertEqual(self.database_cache.fetch_country_code('ipv4',
                'lir', int(ipaddr.IPv4Address('80.16.151.180'))), 'IT')
        self.assertEqual(self.database_cache.fetch_country_code('ipv4',
                'lir', int(ipaddr.IPv4Address('213.95.6.32'))), 'DE')

    def test_lir_ipv6_lookup(self):
        self.assertEqual(self.database_cache.fetch_country_code('ipv6',
                'lir', int(ipaddr.IPv6Address('2001:0658:021A::'))), 'DE')
        self.assertEqual(self.database_cache.fetch_country_code('ipv6',
                'lir', int(ipaddr.IPv6Address('2001:67c:320::'))), 'DE')
        self.assertEqual(self.database_cache.fetch_country_code('ipv6',
                'lir', int(ipaddr.IPv6Address('2001:670:0085::'))), 'FI')


class CheckBlockFinder(BaseBlockfinderTest):
    def test_ipv4_bf(self):
        known_ipv4_assignments = (
                ('MM', ['203.81.64.0/19', '203.81.160.0/20']),
                ('KP', ['175.45.176.0/22']))
        for cc, values in known_ipv4_assignments:
            expected = [(int(ipaddr.IPv4Network(network_str).network_address),
                    int(ipaddr.IPv4Network(network_str).broadcast_address))
                    for network_str in values]
            result = self.database_cache.fetch_assignments('ipv4', cc)
            self.assertEqual(result, expected)

    def test_ipv6_bf(self):
        known_ipv6_assignments = ['2001:200::/35', '2001:200:2000::/35',
                                  '2001:200:4000::/34', '2001:200:8000::/33']
        expected = [(int(ipaddr.IPv6Network(network_str).network_address),
                int(ipaddr.IPv6Network(network_str).broadcast_address))
                for network_str in known_ipv6_assignments]
        result = self.database_cache.fetch_assignments('ipv6', 'JP')
        self.assertEqual(result, expected)


if __name__ == '__main__':
    failures = 0
    for test_class in [CheckReverseLookup, CheckBlockFinder]:
        test_suite = unittest.makeSuite(test_class)
        test_runner = unittest.TextTestRunner(verbosity=2)
        results = test_runner.run(test_suite)
        failures += len(results.errors)
        failures += len(results.failures)
    sys.exit(failures)
