#!/usr/bin/python
import blockfinder
import unittest
import os

# XXX
# add tests to build sqlite dbs, maybe not the whole db
# but a striped down test subset (expecially for the lir)

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

class CheckBuildSqliteDB(unittest.TestCase):
    lir_test = False

    cache_dir = os.path.abspath(os.curdir) + '/testcache/'
    
    lir_urls = """ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz
    ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz"""
    
    delegation_urls = """
        ftp://ftp.arin.net/pub/stats/arin/delegated-arin-latest
        ftp://ftp.ripe.net/ripe/stats/delegated-ripencc-latest
        ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest
        ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest
        ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest
    """
    delegation_files = []   
 
    def setUp(self):
        for url in self.delegation_urls.split():
           filename = url.rpartition('/')
           self.delegation_files.append(filename[-1])
        blockfinder.create_or_replace_lir_table_in_db(self.cache_dir)
    
    
    def test_update_lir(self):
        if(self.lir_test == True):
            blockfinder.update_lir_delegation_cache(self.cache_dir, self.lir_urls, 'Mozilla/5.0')
            # Here I should trim random parts of the file
            # something similar to cat ripe.db.inetnum | head -n $RANDOM | tail -n $RANDOM > file
            for file in "ripe.db.inetnum ripe.db.inet6num":
                blockfinder.extract_info_from_lir_file_and_insert_into_sqlite(self.cache_dir, file)

    def test_update_rir(self):
        result = blockfinder.update_delegation_cache(self.cache_dir,self.delegation_urls, 'Mozilla/5.0')
        self.assertTrue(result)
        result = blockfinder.create_db_and_insert_delegation_into_db(self.cache_dir, self.delegation_urls)        
        self.assertTrue(result)

class CheckBlockFinder(unittest.TestCase):

    # Should we be doing these tests against the test db?
    cache_dir = str(os.path.expanduser('~')) + "/.blockfinder/"
    
   
    # You can add known blocks to the tuple as a list
    # they will be looked up and checked
    knownResults = ( ('mm', ['203.81.64.0/19', 
                            '203.81.160.0/20']),
                    ('kp', ['175.45.176.0/22']))

    def test_ipv4_bf(self):
        blockfinder.verbose = 0
        for cc, values in self.knownResults:
            self.result = blockfinder.use_sql_database_call("ipv4", cc.upper(), self.cache_dir)
            self.assertEqual(self.result, values)


if __name__ == '__main__':
    unittest.main()


