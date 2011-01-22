#!/usr/bin/python
import blockfinder
import unittest
import os
import shutil
import test_data

try:
    import IPy
except ImportError:
    IPy = None


class BlockFinderTestExtras:
    def __init__(self, test_dir="/tmp/blockfinder_test/"):
        self.test_dir = test_dir
        assert self.test_dir == "/tmp/blockfinder_test/", "if you want to change the test directory you will need to change this line!"
        self.block_f = blockfinder.Blockfinder(self.test_dir, "Mozilla")

    def create_new_test_cache_dir(self):
        shutil.rmtree(self.test_dir, True)
        self.block_f.create_blockfinder_cache_dir()
        self.block_f.connect_to_database()
        self.block_f.create_sql_database()

    def load_del_test_data(self):
        delegations = [test_data.return_sub_apnic_del()]
        self.block_f.insert_into_sql_database(delegations)

    def load_lir_test_data(self):
        self.block_f.update_lir_delegation_cache("https://github.com/downloads/d1b/blockfinder/tiny_lir_data_for_test.gz")
        self.block_f.create_or_replace_lir_table_in_db()
        self.block_f.extract_info_from_lir_file_and_insert_into_sqlite("tiny_lir_data_for_test")

    def copy_country_code_xml(self):
        shutil.copy(str(os.path.expanduser('~')) + "/.blockfinder/countrycodes.xml", self.block_f.cache_dir + "countrycodes.xml")

class CheckReverseLookup(unittest.TestCase):
    ipValues = ( (3229318011, '192.123.123.123'),
            (3463778365, '206.117.16.61'),
            (4278190202, '255.0.0.122'),
            (3654084623, '217.204.232.15'),
            (134217728, '8.0.0.0'))

    rirValues = ( ('217.204.232.15', 'GB'),
                  ('188.72.225.100', 'DE'),
                  ('8.8.8.1', 'US'))
    def setUp(self):
        self.block_f = blockfinder.Blockfinder(str(os.path.expanduser('~')) + "/.blockfinder/", "Mozilla")
        self.block_f.connect_to_database()

    def test_rir_lookup(self):
        for ip, cc in self.rirValues:
            result = self.block_f.rir_lookup(ip)
            self.assertEqual(result[0], cc)

    def test_ip_address_to_dec(self):
        for dec, ip in self.ipValues:
            result = blockfinder.ip_address_to_dec(ip)
            self.assertEqual(result, dec)


class CheckBlockFinder(unittest.TestCase):
    def setUp(self):
        self.extra_block_test_f = BlockFinderTestExtras()
        self.block_f = blockfinder.Blockfinder(self.extra_block_test_f.test_dir, "Mozilla")

        self.extra_block_test_f.create_new_test_cache_dir()
        self.extra_block_test_f.load_del_test_data()

    # You can add known blocks to the tuple as a list
    # they will be looked up and checked
    known_ipv4_Results = ( ('mm', ['203.81.160.0/20', '203.81.64.0/19']),
                             ('kp', ['175.45.176.0/22']))

    def test_ipv4_bf(self):
        self.block_f.connect_to_database()
        for cc, values in self.known_ipv4_Results:
            result = self.block_f.use_sql_database("ipv4", cc.upper())
            self.assertEqual(result, values)
        self.block_f.conn.close()
    def test_ipv6_bf(self):
        self.block_f.connect_to_database()
        expected = ['2001:200:2000::/35', '2001:200:4000::/34', '2001:200:8000::/33', '2001:200::/35']
        result = self.block_f.use_sql_database("ipv6", "JP")
        self.assertEqual(result, expected)
        self.block_f.conn.close()

    def test_lir_fetching_and_use_ipv4(self):
        self.block_f.connect_to_database()
        self.extra_block_test_f.load_lir_test_data()
        self.extra_block_test_f.copy_country_code_xml()
        self.assertEqual(self.block_f.rir_or_lir_lookup_ipv4("80.16.151.184", "LIR"), ["IT", "Italy"])
        self.assertEqual(self.block_f.rir_or_lir_lookup_ipv4("80.16.151.180", "LIR"), ["IT", "Italy"])
        self.assertEqual(self.block_f.rir_or_lir_lookup_ipv4("213.95.6.32", "LIR"), ["DE", "Germany"])
        self.block_f.conn.close()

    def test_lir_fetching_and_use_ipv6(self):
        """ ipv6 """
        self.block_f.connect_to_database()
        self.extra_block_test_f.load_lir_test_data()
        self.extra_block_test_f.copy_country_code_xml()
        self.assertEqual(self.block_f.rir_or_lir_lookup_ipv6("2001:0658:021A::", "2001%", "LIR"), u"DE")
        self.assertEqual(self.block_f.rir_or_lir_lookup_ipv6("2001:67c:320::", "2001%", "LIR"), u"DE")
        self.assertEqual(self.block_f.rir_or_lir_lookup_ipv6("2001:670:0085::", "2001%", "LIR"), u"FI")

        self.block_f.conn.close()


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

    def test_ipv4_address_to_dec(self):
        self.assertEqual(blockfinder.ip_address_to_dec("0.0.0.0"), 0)
        self.assertEqual(blockfinder.ip_address_to_dec("4.2.2.2"), 67240450)
        self.assertEqual(blockfinder.ip_address_to_dec("217.204.232.15"), 3654084623)
        self.assertEqual(blockfinder.ip_address_to_dec("255.255.255.255"), 4294967295)

    def test_ipv4_address_to_dec_against_IPy(self):
        if IPy is not None:
            for i in range(0, 255):
                ipaddr = "%s.%s.%s.%s" % (i, i, i, i)
                self.assertEqual(blockfinder.ip_address_to_dec(ipaddr), IPy.IP(ipaddr).int())

    def test_return_first_ip_and_number_in_inetnum(self):
        line = "1.1.1.1 - 1.1.1.2"
        self.assertEqual(blockfinder.return_first_ip_and_number_in_inetnum(line), ("1.1.1.1", 2) )

if __name__ == '__main__':
    for test_class in [CheckReverseLookup, CheckBlockFinder, CheckBasicFunctionOperation]:
        unittest.TextTestRunner(verbosity=2).run(unittest.makeSuite(test_class))

