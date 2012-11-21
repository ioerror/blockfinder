#!/usr/bin/python
import blockfinder
import unittest
import os
import shutil
from tempfile import mkdtemp
import test_data
import ipaddr


class BlockFinderTestExtras:
    def __init__(self):
        self.base_test_dir = mkdtemp()
        self.test_dir = self.base_test_dir + "/test/"
        self.database_cache = blockfinder.DatabaseCache(self.test_dir)
        self.downloader_parser = blockfinder.DownloaderParser(
                self.test_dir, self.database_cache, "Mozilla")
        self.lookup = blockfinder.Lookup(self.test_dir, self.database_cache)

    def create_new_test_cache_dir(self):
        self.downloader_parser.create_blockfinder_cache_dir()
        self.database_cache.connect_to_database()
        self.database_cache.set_db_version()
        self.database_cache.create_assignments_table()

    def load_del_test_data(self):
        self.database_cache.delete_assignments('rir')
        delegations = [test_data.return_sub_apnic_del()]
        rows = []
        for delegation in delegations:
            for entry in delegation:
                source_name = str(entry['registry'])
                country_code = str(entry['cc'])
                if not source_name.isdigit() and country_code != "*":
                    num_type = entry['type']
                    if num_type == 'asn':
                        start_num = end_num = int(entry['start'])
                    elif num_type == 'ipv4':
                        start_num = int(ipaddr.IPAddress(entry['start']))
                        end_num = start_num + long(entry['value']) - 1
                    elif num_type == 'ipv6':
                        network_str = entry['start'] + '/' + \
                                entry['value']
                        network_ipaddr = ipaddr.IPv6Network(network_str)
                        start_num = int(network_ipaddr.network)
                        end_num = int(network_ipaddr.broadcast)
                    self.database_cache.insert_assignment(start_num, \
                            end_num, num_type, country_code, 'rir', \
                            source_name)
        self.database_cache.commit_changes()

    def load_lir_test_data(self):
        self.downloader_parser.update_lir_delegation_cache("https://github.com/downloads/d1b/blockfinder/tiny_lir_data_for_test.gz")
        self.database_cache.delete_assignments('lir')
        self.downloader_parser.extract_info_from_lir_file_and_insert_into_sqlite("tiny_lir_data_for_test")

    def copy_country_code_txt(self):
        shutil.copy(str(os.path.expanduser('~')) + "/.blockfinder/countrycodes.txt", self.test_dir + "countrycodes.txt")

    def clean_up(self):
        shutil.rmtree(self.base_test_dir, True)

class BaseBlockfinderTest(unittest.TestCase):
    """ This is the base blockfinder test class and provides
        a setUp and a tearDown which create and destroy a temporary
        cache directory and database respectively.
    """
    def setUp(self):
        self.extra_block_test_f = BlockFinderTestExtras()
        self.cache_dir = self.extra_block_test_f.test_dir
        self.database_cache = blockfinder.DatabaseCache(self.cache_dir)
        self.downloader_parser = blockfinder.DownloaderParser(
                self.cache_dir, self.database_cache, "Mozilla")
        self.lookup = blockfinder.Lookup(self.cache_dir, self.database_cache)
        self.extra_block_test_f.create_new_test_cache_dir()
        self.extra_block_test_f.load_del_test_data()

    def tearDown(self):
        self.extra_block_test_f.clean_up()

class CheckReverseLookup(BaseBlockfinderTest):
    rirValues = ( ('175.45.176.100', 'KP'),
                  ('193.9.26.0', 'HU'),
                  ('193.9.25.1', 'PL'),
                  ('193.9.25.255', 'PL'),
                  )
    asnValues = ( ('681', 'NZ'),
                ('173', 'JP')
                )

    def tearDown(self):
        self.extra_block_test_f.clean_up()

    def reverse_lookup_cc_matcher(self, num_type, values):
        self.database_cache.connect_to_database()
        self.downloader_parser.download_country_code_file()
        for address, cc in values:
            if num_type == 'ipv4':
                value = int(ipaddr.IPv4Address(address))
            else:
                value = int(address)
            result = self.database_cache.fetch_country_code(num_type, \
                    'rir', value)
            self.assertEqual(result, cc)

    def test_rir_lookup(self):
        self.reverse_lookup_cc_matcher('ipv4', self.rirValues)

    def test_asn_lookup(self):
        self.reverse_lookup_cc_matcher('asn', self.asnValues)

class CheckBlockFinder(BaseBlockfinderTest):
    # You can add known blocks to the tuple as a list
    # they will be looked up and checked
    known_ipv4_Results = (('MM', ['203.81.64.0/19', '203.81.160.0/20']), \
                          ('KP', ['175.45.176.0/22']))
    known_ipv6_Results = ['2001:200::/35', '2001:200:2000::/35', \
                          '2001:200:4000::/34', '2001:200:8000::/33']

    def test_ipv4_bf(self):
        self.database_cache.connect_to_database()
        for cc, values in self.known_ipv4_Results:
            expected = [(int(ipaddr.IPv4Network(network_str).network), \
                    int(ipaddr.IPv4Network(network_str).broadcast)) \
                    for network_str in values]
            result = self.database_cache.fetch_assignments('ipv4', cc)
            self.assertEqual(result, expected)
        self.database_cache.commit_and_close_database()

    def test_ipv6_bf(self):
        self.database_cache.connect_to_database()
        expected = [(int(ipaddr.IPv6Network(network_str).network), \
                int(ipaddr.IPv6Network(network_str).broadcast)) \
                for network_str in self.known_ipv6_Results]
        result = self.database_cache.fetch_assignments('ipv6', 'JP')
        self.assertEqual(result, expected)
        self.database_cache.commit_and_close_database()

    def test_lir_fetching_and_use(self):
        """ test LIR fetching and use. """
        """ ipv4 """
        self.database_cache.connect_to_database()
        self.extra_block_test_f.load_lir_test_data()
        self.downloader_parser.download_country_code_file()
        self.assertEqual(self.database_cache.fetch_country_code('ipv4', \
                'lir', int(ipaddr.IPv4Address('80.16.151.184'))), 'IT')
        self.assertEqual(self.database_cache.fetch_country_code('ipv4', \
                'lir', int(ipaddr.IPv4Address('80.16.151.180'))), 'IT')
        self.assertEqual(self.database_cache.fetch_country_code('ipv4', \
                'lir', int(ipaddr.IPv4Address('213.95.6.32'))), 'DE')

        """ ipv6 """
        self.assertEqual(self.database_cache.fetch_country_code('ipv6', \
                'lir', int(ipaddr.IPv6Address('2001:0658:021A::'))), 'DE')
        self.assertEqual(self.database_cache.fetch_country_code('ipv6', \
                'lir', int(ipaddr.IPv6Address('2001:67c:320::'))), 'DE')
        self.assertEqual(self.database_cache.fetch_country_code('ipv6', \
                'lir', int(ipaddr.IPv6Address('2001:670:0085::'))), 'FI')
        self.database_cache.commit_and_close_database()


    def test_db_version(self):
        """ test the handling of the db version information of the database cache. """
        self.database_cache.connect_to_database()
        self.database_cache.set_db_version()
        self.assertEqual(self.database_cache.get_db_version(), self.database_cache.db_version)

if __name__ == '__main__':
    for test_class in [CheckReverseLookup, CheckBlockFinder]:
        unittest.TextTestRunner(verbosity=2).run(unittest.makeSuite(test_class))

