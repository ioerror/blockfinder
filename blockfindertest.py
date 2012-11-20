#!/usr/bin/python
import blockfinder
import unittest
import os
import shutil
from tempfile import mkdtemp
import test_data


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
        self.database_cache.create_sql_database()

    def load_del_test_data(self):
        delegations = [test_data.return_sub_apnic_del()]
        rows = []
        for delegation in delegations:
            for entry in delegation:
                registry = str(entry['registry'])
                if not registry.isdigit() and str (entry['cc']) !="*":
                    temp_row = [entry['registry'], entry['cc'], entry['start'], \
                        entry['value'], entry['date'], entry['status'], entry['type']]
                    rows.append(temp_row)
        self.database_cache.insert_into_sql_database(rows)

    def load_lir_test_data(self):
        self.downloader_parser.update_lir_delegation_cache("https://github.com/downloads/d1b/blockfinder/tiny_lir_data_for_test.gz")
        self.database_cache.create_or_replace_lir_table_in_db()
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

    def reverse_lookup_cc_matcher(self, method, values):
        self.database_cache.connect_to_database()
        self.downloader_parser.download_country_code_file()
        for value, cc in values:
            result = method(value)
            self.assertEqual(result, cc)

    def test_rir_lookup(self):
        method = self.database_cache.rir_lookup
        self.reverse_lookup_cc_matcher(method, self.rirValues)

    def test_asn_lookup(self):
        method = self.database_cache.asn_lookup
        self.reverse_lookup_cc_matcher(method, self.asnValues)

class CheckBlockFinder(BaseBlockfinderTest):
    # You can add known blocks to the tuple as a list
    # they will be looked up and checked
    known_ipv4_Results = ( ('mm', ['203.81.160.0/20', '203.81.64.0/19']),
                             ('kp', ['175.45.176.0/22']))

    def test_ipv4_bf(self):
        self.database_cache.connect_to_database()
        for cc, values in self.known_ipv4_Results:
            result = self.database_cache.use_sql_database("ipv4", cc.upper())
            self.assertEqual(result, values)
        self.database_cache.commit_and_close_database()
    def test_ipv6_bf(self):
        self.database_cache.connect_to_database()
        expected = ['2001:200:2000::/35', '2001:200:4000::/34', '2001:200:8000::/33', '2001:200::/35']
        result = self.database_cache.use_sql_database("ipv6", "JP")
        self.assertEqual(result, expected)
        self.database_cache.commit_and_close_database()

    def test_lir_fetching_and_use(self):
        """ test LIR fetching and use. """
        """ ipv4 """
        self.database_cache.connect_to_database()
        self.extra_block_test_f.load_lir_test_data()
        self.downloader_parser.download_country_code_file()
        self.assertEqual(self.database_cache._rir_or_lir_lookup_ipv4("80.16.151.184", "LIR"), "IT")
        self.assertEqual(self.database_cache._rir_or_lir_lookup_ipv4("80.16.151.180", "LIR"), "IT")
        self.assertEqual(self.database_cache._rir_or_lir_lookup_ipv4("213.95.6.32", "LIR"), "DE")

        """ ipv6 """
        self.assertEqual(self.database_cache.rir_or_lir_lookup_ipv6("2001:0658:021A::", "2001%", "LIR"), u"DE")
        self.assertEqual(self.database_cache.rir_or_lir_lookup_ipv6("2001:67c:320::", "2001%", "LIR"), u"DE")
        self.assertEqual(self.database_cache.rir_or_lir_lookup_ipv6("2001:670:0085::", "2001%", "LIR"), u"FI")
        self.database_cache.commit_and_close_database()


    def test_db_version(self):
        """ test the handling of the db version information of the database cache. """
        self.database_cache.connect_to_database()
        self.assertEqual(self.database_cache.get_db_version(), None)
        self.database_cache.set_db_version()
        self.assertEqual(self.database_cache.get_db_version(), self.database_cache.db_version)

if __name__ == '__main__':
    for test_class in [CheckReverseLookup, CheckBlockFinder]:
        unittest.TextTestRunner(verbosity=2).run(unittest.makeSuite(test_class))

