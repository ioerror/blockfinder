#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# For the people of Smubworld!
import os
import time
import optparse
import sys
import sqlite3
import hashlib
import gzip
import zipfile
import re
import bz2
from math import log

if sys.version_info[0] >= 3:
    from configparser import ConfigParser
    import ipaddress as ipaddr
    from urllib.request import (urlopen, Request)
    from urllib.error import URLError
    long = int
else:
    from ConfigParser import SafeConfigParser as ConfigParser
    from urllib2 import (urlopen, Request, URLError)
    try:
        from embedded_ipaddr import ipaddr
        ipaddr.ip_address = ipaddr.IPAddress
    except:
        import ipaddress as ipaddr

is_win32 = (sys.platform == "win32")

__program__ = 'blockfinder'
__url__ = 'https://github.com/ioerror/blockfinder/'
__author__ = 'Jacob Appelbaum <jacob@appelbaum.net>, David <db@d1b.org>'
__copyright__ = 'Copyright (c) 2010'
__license__ = 'See LICENSE for licensing information'
__version__ = '4.0.0'

try:
    from future import antigravity
except ImportError:
    antigravity = None


class DatabaseCache(object):

    def __init__(self, cache_dir, verbose=False):
        self.cache_dir = cache_dir
        self.verbose = verbose
        self.cursor = None
        self.conn = None
        self.db_version = "0.0.4"
        self.db_path = os.path.join(self.cache_dir + "sqlitedb")

    def erase_database(self):
        """ Erase the database file. """
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def connect_to_database(self):
        """ Connect to the database cache, possibly after creating it if
            it doesn't exist yet, or after making sure an existing
            database cache has the correct version.  Return True if a
            connection could be established, False otherwise. """
        if not os.path.exists(self.cache_dir):
            if self.verbose:
                print("Initializing the cache directory...")
            os.mkdir(self.cache_dir)
        if os.path.exists(self.db_path):
            cache_version = self.get_db_version()
            if not cache_version:
                cache_version = "0.0.1"
            if cache_version != self.db_version:
                print(("The existing database cache uses version %s, "
                       "not the expected %s." % (cache_version,
                                                 self.db_version)))
                return False
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.create_assignments_table()
        self.create_asn_description_table()
        self.create_asn_assignments_table()
        return True

    def __get_default_config_file_obj(self):
        open_flags = 'r+'
        file_path = os.path.join(self.cache_dir, 'db.cfg')
        if not os.path.exists(file_path):
            open_flags = 'w+'
        return open(file_path, open_flags)

    def _get_db_config(self, file_obj=None):
        """ Return the database configuration object from the provided
            file_obj if provided, otherwise from the default database
            configuration file. """
        if file_obj is None:
            file_obj = self.__get_default_config_file_obj()
        config = ConfigParser()
        if sys.version_info[0] >= 3:
            config.read_file(file_obj)
        else:
            config.readfp(file_obj)
        file_obj.close()
        return config

    def set_db_version(self, file_obj=None):
        """ Set the database version string in the config file. """
        if file_obj is None:
            file_obj = self.__get_default_config_file_obj()
        config = self._get_db_config()
        if not config.has_section('db'):
            config.add_section('db')
        config.set('db', 'version', self.db_version)
        config.write(file_obj)
        file_obj.close()

    def get_db_version(self):
        """ Read and return the database version string from the config
            file. """
        config = self._get_db_config()
        if not config.has_section('db'):
            return None
        return config.get('db', 'version')

    def commit_and_close_database(self):
        self.conn.commit()
        self.cursor.close()

    def create_assignments_table(self):
        """ Create the assignments table that stores all assignments from
            IPv4/IPv6/ASN to country code.  Blocks are stored as first hex
            of and first hex after the assignment.  Numbers are stored
            as hex strings, because SQLite's INTEGER type only holds up to
            63 unsigned bits, which is not enough to store a /64 IPv6
            block.  Hex strings have leading zeros, with IPv6 addresses
            being 33 hex characters long and IPv4 addresses and ASN being
            9 hex characters long.  The first number after an assignment
            range is stored instead of the last number in the range to
            facilitate comparisons with neighboring ranges. """
        sql = ('CREATE TABLE IF NOT EXISTS assignments(start_hex TEXT, '
               'next_start_hex TEXT, num_type TEXT, country_code TEXT, '
               'source_type TEXT, source_name TEXT)')
        self.cursor.execute(sql)
        self.conn.commit()

    def create_asn_description_table(self):
        """ Create the assignments table that stores all the descriptions
            associated with ASNs. """
        sql = ('CREATE TABLE IF NOT EXISTS asn_descriptions(as_num INT, '
               'source_name TEXT, description TEXT)')
        self.cursor.execute(sql)
        sql = ('CREATE INDEX IF NOT EXISTS DescriptionsByASN ON '
               'asn_descriptions ( as_num )')
        self.cursor.execute(sql)
        self.conn.commit()

    def create_asn_assignments_table(self):
        """ Create the assignments table that stores the assignments from
            IPv4 to ASN """
        # XXX: IPv6 not yet supported. (Not available from routeviews?)
        sql = ('CREATE TABLE IF NOT EXISTS asn_assignments(start_hex TEXT, '
               'next_start_hex TEXT, num_type TEXT, as_num INT, '
               'source_type TEXT, source_name TEXT, PRIMARY KEY(start_hex, '
               'next_start_hex))')
        self.cursor.execute(sql)
        sql = ('CREATE INDEX IF NOT EXISTS ASNEntriesByStartHex on '
               'asn_assignments ( start_hex )')
        self.cursor.execute(sql)
        self.conn.commit()

    def delete_assignments(self, source_type):
        """ Delete all assignments from the database cache matching a
            given source type ("rir", "lir", etc.). """
        sql = 'DELETE FROM assignments WHERE source_type = ?'
        self.cursor.execute(sql, (source_type, ))
        self.conn.commit()

    def delete_asn_descriptions(self):
        """ Delete all asn descriptions from the database cache. """
        sql = 'DELETE FROM asn_descriptions'
        self.cursor.execute(sql)
        self.conn.commit()

    def delete_asn_assignments(self):
        """ Delete all the bgp netblock to as entries """
        sql = 'DELETE FROM asn_assignments'
        self.cursor.execute(sql)
        self.conn.commit()

    def insert_assignment(self, start_num, end_num, num_type,
                          country_code, source_type, source_name):
        """ Insert an assignment into the database cache, without
            commiting after the insertion. """
        sql = ('INSERT INTO assignments (start_hex, next_start_hex, '
               'num_type, country_code, source_type, source_name) '
               'VALUES (?, ?, ?, ?, ?, ?)')
        if num_type == 'ipv6':
            start_hex = '%033x' % start_num
            next_start_hex = '%033x' % (end_num + 1)
        else:
            start_hex = '%09x' % start_num
            next_start_hex = '%09x' % (end_num + 1)
        country_code = normalize_country_code(country_code)
        self.cursor.execute(sql, (start_hex, next_start_hex, num_type,
                                  country_code, source_type, source_name))

    def insert_asn_description(self, asn, source_name, description):
        sql = ('INSERT INTO asn_descriptions '
               '(as_num, source_name, description) '
               'VALUES (?, ?, ?)')
        self.cursor.execute(sql, (asn, source_name, unicode(description)))

    def insert_asn_assignment(self, start_num, end_num, num_type, asn,
                              source_type, source_name):
        # XXX: This is sqlite specific syntax
        sql = ('INSERT OR IGNORE INTO asn_assignments (start_hex, '
               'next_start_hex, num_type, as_num, source_type, source_name) '
               'VALUES (?, ?, ?, ?, ?, ?)')
        if num_type == 'ipv6':
            start_hex = '%033x' % start_num
            next_start_hex = '%033x' % (end_num + 1)
        else:
            start_hex = '%09x' % start_num
            next_start_hex = '%09x' % (end_num + 1)
        self.cursor.execute(sql, (start_hex, next_start_hex, num_type, asn,
                                  source_type, source_name))

    def commit_changes(self):
        """ Commit changes, e.g., after inserting assignments into the
            database cache. """
        self.conn.commit()

    def fetch_assignments(self, num_type, country_code):
        """ Fetch all assignments from the database cache matching the
            given number type ("asn", "ipv4", or "ipv6") and country code.
            The result is a sorted list of tuples containing (start_num,
            end_num). """
        sql = ('SELECT start_hex, next_start_hex FROM assignments '
               'WHERE num_type = ? AND country_code = ? '
               'ORDER BY start_hex')
        self.cursor.execute(sql, (num_type, country_code))
        result = []
        for row in self.cursor:
            result.append((long(row[0], 16), long(row[1], 16) - 1))
        return result

    def fetch_country_code(self, num_type, source_type, lookup_num):
        """ Fetch the country code from the database cache that is
            assigned to the given number (e.g., IPv4 address in decimal
            notation), number type (e.g., "ipv4"), and source type (e.g.,
            "rir"). """
        sql = ('SELECT country_code FROM assignments WHERE num_type = ? '
               'AND source_type = ? AND start_hex <= ? '
               'AND next_start_hex > ?')
        if num_type == 'ipv6':
            lookup_hex = '%033x' % long(lookup_num)
        else:
            lookup_hex = '%09x' % long(lookup_num)
        self.cursor.execute(sql, (num_type, source_type, lookup_hex,
                                  lookup_hex))
        row = self.cursor.fetchone()
        if row:
            return row[0]

    def fetch_country_blocks_in_other_sources(self, first_country_code):
        """ Fetch all assignments matching the given country code, then look
            up to which country code(s) the same number ranges are assigned in
            other source types.  Return 8-tuples containing (1) first source
            type, (2) first and (3) last number of the assignment in the first
            source type, (4) second source type, (5) first and (6) last number
            of the assignment in the second source type, (7) country code in
            the second source type, and (8) number type. """
        sql = ('SELECT first.source_type, first.start_hex, '
               'first.next_start_hex, second.source_type, '
               'second.start_hex, second.next_start_hex, '
               'second.country_code, first.num_type '
               'FROM assignments AS first '
               'JOIN assignments AS second '
               'WHERE first.country_code = ? '
               'AND first.start_hex <= second.next_start_hex '
               'AND first.next_start_hex >= second.start_hex '
               'AND first.num_type = second.num_type '
               'ORDER BY first.source_type, first.start_hex, '
               'second.source_type, second.start_hex')
        self.cursor.execute(sql, (first_country_code, ))
        result = []
        for row in self.cursor:
            result.append((str(row[0]), long(row[1], 16),
                           long(row[2], 16) - 1, str(row[3]), long(row[4], 16),
                           long(row[5], 16) - 1, str(row[6]), str(row[7])))
        return result

    def fetch_org_by_ip_address(self, lookup_str, num_type):
        if num_type == 'ipv4':
            lookup_hex = '%09x' % long(int(lookup_str))
        else:
            lookup_hex = '%033x' % long(int(lookup_str))
        sql = ('SELECT asn_descriptions.as_num, asn_descriptions.description, '
               'asn_assignments.start_hex, asn_assignments.next_start_hex '
               'FROM asn_descriptions JOIN asn_assignments ON '
               'asn_assignments.as_num = asn_descriptions.as_num '
               'WHERE num_type = ? AND start_hex <= ? AND next_start_hex > ?')
        self.cursor.execute(sql, (num_type, lookup_hex, lookup_hex))
        row = self.cursor.fetchall()
        if row:
            return row

    def fetch_org_by_ip_range(self, lookup_start, lookup_end, num_type):
        if num_type == 'ipv4':
            lookup_start_hex = '%09x' % long(int(lookup_start))
            lookup_end_hex = '%09x' % long(int(lookup_end))
        else:
            lookup_start_hex = '%033x' % long(int(lookup_start))
            lookup_end_hex = '%033x' % long(int(lookup_end))

        sql = ('SELECT asn_descriptions.as_num, asn_descriptions.description, '
               'asn_assignments.start_hex, asn_assignments.next_start_hex '
               'FROM asn_descriptions JOIN asn_assignments ON '
               'asn_assignments.as_num = asn_descriptions.as_num '
               'WHERE num_type = ? AND start_hex >= ? AND next_start_hex <= ?')
        self.cursor.execute(sql, (num_type, lookup_start_hex, lookup_end_hex))
        row = self.cursor.fetchall()
        if row:
            return row

    def _concatenate_and_write(
            self, records, write_function=None, record_filter=None, bits=32):
        netblocks = []
        for row in records:
            try:
                start_hex, next_start_hex, record = \
                    long(row[0], 16), long(row[1], 16), str(row[2])
                nb = bits - int(log(next_start_hex - start_hex, 2))
                net = ipaddr.IPNetwork("%s/%d" %
                                       (ipaddr.IPAddress(start_hex), nb))
                if callable(record_filter):
                    record = record_filter(record)
            except ValueError:
                continue

            # Concatenate adjacent blocks of the same country
            if netblocks and netblocks[-1][1] == record:
                pn = netblocks[-1][0]
                nb = bits - int(log(int(net.network) +
                                    int(net.numhosts) - int(pn.network), 2))
                netblocks[-1] = (ipaddr.IPNetwork("%s/%d" %
                                                  (pn.network, nb)), record)

            # if the adjacent blocks aren't the same country,
            # write the last block out to csv and add the new block
            # to the list for possible concatenation
            elif netblocks:
                prev_n, prev_record = netblocks.pop()
                if write_function:
                    write_function(prev_n, prev_record)
                netblocks.append((net, record))

            # this is the base case
            else:
                netblocks.append((net, record))

    def export_asn(self, filename, num_type):
        """ Export assignments to the CSV format used to build the
            geoip-database asn lookup
        """
        sql = ('SELECT start_hex, next_start_hex, as_num '
               'FROM asn_assignments WHERE num_type = ? ORDER BY start_hex')
        self.cursor.execute(sql, (num_type,))
        try:
            f = open(filename, 'w')
        except IOError:
            print("Unable to open %s" % filename)
            return

        def write_csv_line(network, asn):
            # XXX: wild guess
            f.write(""""%s","%s","%d","%d","%s"\n""" % (network.network,
                                                        network.broadcast,
                                                        int(network.network),
                                                        int(network.broadcast),
                                                        asn))
        if num_type == 'ipv6':
            ip_bits = 128
        elif num_type == 'ipv4':
            ip_bits = 32
        else:
            return

        self._concatenate_and_write(self.cursor, write_function=write_csv_line,
                                    bits=ip_bits)
        f.close()

    def export_geoip(self, lookup, filename, num_type):
        """ Export assignments to the CSV format used to build the
            geoip-database package """

        sql = ('SELECT start_hex, next_start_hex, country_code '
               'FROM assignments WHERE num_type = ? ORDER BY start_hex')
        self.cursor.execute(sql, (num_type,))

        try:
            f = open(filename, 'w')
        except IOError:
            print("Unable to open %s" % filename)
            return

        def write_csv_line(network, country_code):
            country_name = lookup.get_name_from_country_code(country_code)
            if country_name:
                country_name = country_name.split(
                    "#")[0].strip()  # Drop comments
            f.write(""""%s","%s","%d","%d","%s","%s"\n""" % (
                network.network,
                network.broadcast,
                int(network.network),
                int(network.broadcast),
                country_code,
                country_name))

        if num_type == 'ipv6':
            ip_bits = 128
        elif num_type == 'ipv4':
            ip_bits = 32
        else:
            return

        self._concatenate_and_write(self.cursor, write_function=write_csv_line,
                                    record_filter=str.upper, bits=ip_bits)
        f.close()


class DownloaderParser(object):

    def __init__(self, cache_dir, database_cache, user_agent,
                 verbose=False):
        self.cache_dir = cache_dir
        self.database_cache = database_cache
        self.user_agent = user_agent
        self.verbose = verbose

    MAXMIND_URLS = """
        http://geolite.maxmind.com/download/geoip/database/GeoIPCountryCSV.zip
        http://geolite.maxmind.com/download/geoip/database/GeoIPv6.csv.gz
    """

    RIR_URLS = """
        ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest
        ftp://ftp.ripe.net/ripe/stats/delegated-ripencc-latest
        ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest
        ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest
        ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest
    """

    LIR_URLS = """
        ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz
        ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz
    """

    COUNTRY_CODE_URL = ("http://www.iso.org/iso/home/standards/country_codes/"
                        "country_names_and_code_elements_txt-temp.htm")

    ASN_DESCRIPTION_URL = "http://www.cidr-report.org/as2.0/autnums.html"

    ASN_ASSIGNMENT_URLS = [
        ('http://archive.routeviews.org/oix-route-views/'
         'oix-full-snapshot-latest.dat.bz2'),
    ]

    def download_maxmind_files(self):
        """ Download all LIR delegation urls. """
        for maxmind_url in self.MAXMIND_URLS.split():
            self._download_to_cache_dir(maxmind_url)

    def download_rir_files(self):
        """ Download all RIR delegation files including md5 checksum. """
        for rir_url in self.RIR_URLS.split():
            rir_md5_url = rir_url + '.md5'
            self._download_to_cache_dir(rir_url)
            self._download_to_cache_dir(rir_md5_url)

    def download_lir_files(self):
        """ Download all LIR delegation urls. """
        for lir_url in self.LIR_URLS.split():
            self._download_to_cache_dir(lir_url)

    def download_country_code_file(self):
        """ Download and save the latest semicolon-separated open country
            codes file. """
        self._download_to_cache_dir(self.COUNTRY_CODE_URL)

    def download_asn_description_file(self):
        """ Download and save the latest ASN to Name report from
            cidr-report.org"""
        self._download_to_cache_dir(self.ASN_DESCRIPTION_URL)

    def download_asn_assignment_files(self):
        """ Download and save the latest routing snapshots. """
        for assignment_url in self.ASN_ASSIGNMENT_URLS:
            self._download_to_cache_dir(assignment_url)

    def _download_to_cache_dir(self, url):
        """ Fetch a resource (with progress bar) and store contents to the
            local cache directory under the file name given in the URL. """
        if not os.path.exists(self.cache_dir):
            if self.verbose:
                print("Initializing the cache directory...")
            os.mkdir(self.cache_dir)
        filename = url.split('/')[-1]
        if self.verbose:
            print(url)
        req = Request(url)
        if self.user_agent:
            req.add_header('User-Agent', self.user_agent)
        # TODO Allow use of a proxy.
        # req.set_proxy(host, type)
        try:
            fetcher = urlopen(req)
        except URLError as err:
            msg = "An error occurred while attempting to cache file from:"
            print(("%s\n\t%s\n\t%s" % (msg, url, str(err))))
            return
        length_header = fetcher.headers.get("Content-Length")
        expected_bytes = -1
        if length_header:
            expected_bytes = int(length_header)
            print(("Fetching %d kilobytes" %
                   round(float(expected_bytes / 1024), 2)))
        download_started = time.time()
        output_file = open(os.path.join(self.cache_dir, filename), "wb")
        received_bytes, seconds_elapsed = 0, 0
        while True:
            seconds_elapsed = time.time() - download_started
            if expected_bytes >= 0:
                self._update_progress_bar(received_bytes, expected_bytes,
                                          seconds_elapsed)
            chunk = fetcher.read(1024)
            if len(chunk) == 0:
                if expected_bytes >= 0 and received_bytes != expected_bytes:
                    print(("Expected %s bytes, only received %s" %
                           (expected_bytes, received_bytes)))
                print("")
                break
            received_bytes += len(chunk)
            output_file.write(chunk)
        output_file.close()

    def _update_progress_bar(self, received_bytes, expected_bytes,
                             seconds_elapsed):
        """ Write a progress bar to the console. """
        if is_win32:
            rows = 100  # use some WinCon function for these?
            columns = 80  # but not really important.
            EOL = "\r"
        else:
            rows, columns = list(map(int, os.popen('stty size', 'r'
                                                   ).read().split()))
            EOL = "\x1b[G"
        if seconds_elapsed == 0:
            seconds_elapsed = 1
        percent_done = float(received_bytes) / float(expected_bytes)
        caption = "%.2f K/s" % (received_bytes / 1024 / seconds_elapsed)
        width = columns - 4 - len(caption)
        sys.stdout.write("[%s>%s] %s%s" % (
            "=" * int(percent_done * width),
            "." * (width - int(percent_done * width)), caption, EOL))
        sys.stdout.flush()

    def check_rir_file_mtimes(self):
        """ Return True if the mtime of any RIR file in our cache directory
            is > 24 hours, False otherwise. """
        if not os.path.exists(self.cache_dir):
            return False
        for rir_url in self.RIR_URLS.split():
            rir_path = os.path.join(self.cache_dir,
                                    rir_url.split('/')[-1])
            if os.path.exists(rir_path):
                rir_stat = os.stat(rir_path)
                if (time.time() - rir_stat.st_mtime) > 86400:
                    return True
        return False

    def verify_rir_files(self):
        """ Compute md5 checksums of all RIR files, compare them to the
            provided .md5 files, and return True if the two checksums match,
            or False otherwise. """
        for rir_url in self.RIR_URLS.split():
            rir_path = os.path.join(self.cache_dir,
                                    rir_url.split('/')[-1])
            rir_md5_path = os.path.join(self.cache_dir,
                                        rir_url.split('/')[-1] + '.md5')
            if not os.path.exists(rir_md5_path) or \
                    not os.path.exists(rir_path):
                continue
            rir_md5_file = open(rir_md5_path, 'r')
            expected_checksum = rir_md5_file.read()
            rir_md5_file.close()
            if "=" in expected_checksum:
                expected_checksum = expected_checksum.split("=")[-1].strip()
            elif expected_checksum == "":
                if self.verbose:
                    print("No checksum... skipping verification...")
                continue
            else:
                regex = re.compile("[a-f0-9]{32}")
                regres = regex.findall(expected_checksum)
                if len(regres) > 1:
                    print("Error: mutiple checksum found")
                elif len(regres) < 1:
                    print("Error: no checksum found")
                else:
                    expected_checksum = regres[0]
            computed_checksum = ""
            rir_file = open(rir_path, 'rb')
            rir_data = rir_file.read()
            rir_file.close()
            computed_checksum = str(hashlib.md5(rir_data).hexdigest())
            if expected_checksum != computed_checksum:
                print(("The computed md5 checksum of %s, %s, does *not* "
                       "match the provided checksum %s!" %
                       (rir_path, computed_checksum, expected_checksum)))

    def parse_maxmind_files(self, maxmind_urls=None):
        """ Parse locally cached MaxMind files and insert assignments to the
            local database cache, overwriting any existing MaxMind
            assignments. """
        if not maxmind_urls:
            maxmind_urls = self.MAXMIND_URLS.split()
        self.database_cache.delete_assignments('maxmind')
        for maxmind_url in maxmind_urls:
            maxmind_path = os.path.join(self.cache_dir,
                                        maxmind_url.split('/')[-1])
            if not os.path.exists(maxmind_path):
                print("Unable to find %s." % maxmind_path)
                continue
            if maxmind_path.endswith('.zip'):
                maxmind_zip_path = zipfile.ZipFile(maxmind_path)
                for contained_filename in maxmind_zip_path.namelist():
                    content = maxmind_zip_path.read(contained_filename)
                    self._parse_maxmind_content(content, 'maxmind',
                                                'maxmind')
                maxmind_zip_path.close()
            elif maxmind_path.endswith('.gz'):
                gzip_file = gzip.open(maxmind_path)
                content = gzip_file.read()
                self._parse_maxmind_content(content, 'maxmind', 'maxmind')
                gzip_file.close()
        self.database_cache.commit_changes()

    def import_maxmind_file(self, maxmind_path):
        self.database_cache.delete_assignments(maxmind_path)
        if not os.path.exists(maxmind_path):
            print("Unable to find %s." % maxmind_path)
            return
        with open(maxmind_path, 'r') as f:
            content = f.read()
        self._parse_maxmind_content(content, maxmind_path, maxmind_path)
        self.database_cache.commit_changes()

    def _parse_maxmind_content(self, content, source_type, source_name):
        keys = ['start_str', 'end_str', 'start_num', 'end_num',
                'country_code', 'country_name']
        for line in content.decode('utf-8').split('\n'):
            if len(line.strip()) == 0 or line.startswith("#"):
                continue
            line = line.replace('"', '').replace(' ', '').strip()
            parts = line.split(',')
            entry = dict((k, v) for k, v in zip(keys, parts))
            start_num = int(entry['start_num'])
            end_num = int(entry['end_num'])
            country_code = str(entry['country_code'])
            start_ipaddr = ipaddr.ip_address(entry['start_str'])
            if isinstance(start_ipaddr, ipaddr.IPv4Address):
                num_type = 'ipv4'
            else:
                num_type = 'ipv6'
            self.database_cache.insert_assignment(
                start_num, end_num,
                num_type,
                country_code,
                source_type,
                source_name)

    def parse_rir_files(self, rir_urls=None):
        """ Parse locally cached RIR files and insert assignments to the local
            database cache, overwriting any existing RIR assignments. """
        if not rir_urls:
            rir_urls = self.RIR_URLS.split()
        self.database_cache.delete_assignments('rir')
        keys = "registry country_code type start value date status"
        for rir_url in rir_urls:
            rir_path = os.path.join(self.cache_dir,
                                    rir_url.split('/')[-1])
            if not os.path.exists(rir_path):
                print("Unable to find %s." % rir_path)
                continue
            rir_file = open(rir_path, 'r')
            for line in rir_file:
                if line.startswith("#"):
                    continue
                entry = dict((k, v) for k, v in
                             zip(keys.split(), line.strip().split("|")))
                source_name = str(entry['registry'])
                country_code = str(entry['country_code'])
                if source_name.replace(
                        ".", "", 1).isdigit() or country_code == "*":
                    continue
                num_type = entry['type']
                if num_type == 'asn':
                    start_num = end_num = int(entry['start'])
                elif num_type == 'ipv4':
                    start_num = int(ipaddr.IPv4Address(entry['start']))
                    end_num = start_num + int(entry['value']) - 1
                elif num_type == 'ipv6':
                    network_str = entry['start'] + '/' + entry['value']
                    network_ipaddr = ipaddr.IPv6Network(network_str)
                    start_num = int(network_ipaddr.network_address)
                    end_num = int(network_ipaddr.broadcast_address)
                self.database_cache.insert_assignment(
                    start_num,
                    end_num,
                    num_type,
                    country_code,
                    'rir',
                    source_name)
            rir_file.close()
        self.database_cache.commit_changes()

    def parse_lir_files(self, lir_urls=None):
        """ Parse locally cached LIR files and insert assignments to the local
            database cache, overwriting any existing LIR assignments. """
        if not lir_urls:
            lir_urls = self.LIR_URLS.split()
        self.database_cache.delete_assignments('lir')
        for lir_url in lir_urls:
            lir_path = os.path.join(self.cache_dir,
                                    lir_url.split('/')[-1])
            if not os.path.exists(lir_path):
                print("Unable to find %s." % lir_path)
                continue
            if lir_path.endswith('.gz'):
                lir_file = gzip.open(lir_path)
            else:
                lir_file = open(lir_path)
            start_num = 0
            end_num = 0
            country_code = ""
            entry = False
            num_type = ""
            for line in lir_file:
                line = line.decode('utf-8', 'ignore').replace("\n", "")
                if line == "":
                    entry = False
                    start_num, end_num, country_code, num_type = 0, 0, "", ""
                elif not entry and "inetnum:" in line:
                    try:
                        line = line.replace("inetnum:", "").strip()
                        start_str = line.split("-")[0].strip()
                        end_str = line.split("-")[1].strip()
                        start_num = int(ipaddr.IPv4Address(start_str))
                        end_num = int(ipaddr.IPv4Address(end_str))
                        entry = True
                        num_type = 'ipv4'
                    except Exception as e:
                        if self.verbose:
                            print(repr(e), line)
                elif not entry and "inet6num:" in line:
                    try:
                        network_str = line.replace("inet6num:", "").strip()
                        network_ipaddr = ipaddr.IPv6Network(network_str)
                        start_num = int(network_ipaddr.network_address)
                        end_num = int(network_ipaddr.broadcast_address)
                        entry = True
                        num_type = 'ipv6'
                    except Exception as e:
                        if self.verbose:
                            print(repr(e), line)
                elif entry and "country:" in line:
                    country_code = line.replace("country:", "").strip()
                    self.database_cache.insert_assignment(
                        start_num,
                        end_num,
                        num_type,
                        country_code,
                        'lir',
                        'ripencc')
            lir_file.close()
        self.database_cache.commit_changes()

    def parse_asn_description_file(self, asn_description_url=None):
        """ Parse locally cached ASN to Description mappings and insert
            mappings to the local database cache, overwriting any existing ASN
            to Name assignments. """
        if not asn_description_url:
            asn_description_url = self.ASN_DESCRIPTION_URL
        self.database_cache.delete_asn_descriptions()
        asn_description_path = os.path.join(self.cache_dir,
                                            asn_description_url.split('/')[-1])
        asn_descriptions = open(asn_description_path)
        source_name = 'cidr_report'
        skiplen = len('<a href="/cgi-bin/as-report?as=AS')
        for line in asn_descriptions:
            try:
                asn, _name = line[skiplen:].split('&view=2.0')
                description = _name.split('</a>')[1].strip()
                self.database_cache.insert_asn_description(asn, source_name,
                                                           description)
            except ValueError:
                pass
        self.database_cache.commit_changes()
        asn_descriptions.close()

    def parse_asn_assignment_files(self, asn_assignment_urls=None):
        if not asn_assignment_urls:
            asn_assignment_urls = self.ASN_ASSIGNMENT_URLS
        self.database_cache.delete_asn_assignments()
        for asn_assignment_url in asn_assignment_urls:
            asn_assignment_path = os.path.join(
                self.cache_dir,
                asn_assignment_url.split('/')[-1])
            if not os.path.exists(asn_assignment_path):
                print("Unable to find %s." % asn_assignment_path)
                continue
            if asn_assignment_path.endswith('.bz2'):
                b = bz2.BZ2File(asn_assignment_path)
                for line in b:
                    if line.startswith("*"):
                        l = line.split()
                        netblock, path = l[1], l[6:-1]
                        nexthop, metric, locprf, weight = l[
                            2], l[3], l[4], l[5]

                        network = ipaddr.IPNetwork(netblock)
                        # XXX add support for other sources too
                        source_type = 'bgp_snapshot'
                        source_name = 'routeviews'

                        if isinstance(network, ipaddr.IPv4Network):
                            num_type = "ipv4"
                        else:
                            num_type = "ivp6"

                        self.database_cache.insert_asn_assignment(
                            int(network.network),
                            int(network.broadcast),
                            num_type,
                            path[-1],
                            source_type,
                            source_name)


class Lookup(object):

    def __init__(self, cache_dir, database_cache, verbose=False):
        self.cache_dir = cache_dir
        self.database_cache = database_cache
        self.verbose = verbose
        self.map_co = None
        self.build_country_code_dictionary()

    def build_country_code_dictionary(self):
        """ Return a dictionary mapping country name to the country
            code. """
        country_code_path = os.path.join(
            self.cache_dir,
            'country_names_and_code_elements_txt-temp.htm')
        if not os.path.exists(country_code_path):
            return
        self.map_co = {}
        country_code_file = open(country_code_path, 'r')
        for line in country_code_file:
            if line == "" or line.startswith("Country ") or ";" not in line:
                continue
            country_name, country_code = line.strip().split(";")
            country_name = ' '.join([part.capitalize() for part in
                                     country_name.split(" ")])
            self.map_co[country_name] = country_code
        country_code_file.close()

    def knows_country_names(self):
        return self.map_co is not None

    def get_name_from_country_code(self, cc_code):
        if not self.knows_country_names():
            return
        country_name = [(key, value) for (key, value) in
                        list(self.map_co.items()) if value == cc_code]
        if len(country_name) > 0:
            return country_name[0][0]

    def get_country_code_from_name(self, country_name):
        """ Return the country code for a given country name. """
        if not self.knows_country_names():
            return
        cc_code = [self.map_co[key] for key in list(self.map_co.keys()) if
                   key.upper().startswith(country_name.upper())]
        if len(cc_code) > 0:
            return cc_code[0]

    def lookup_ipv6_address(self, lookup_ipaddr):
        print("Reverse lookup for: " + str(lookup_ipaddr))
        for source_type in ['maxmind', 'rir', 'lir']:
            cc = self.database_cache.fetch_country_code(
                'ipv6',
                source_type,
                int(lookup_ipaddr))
            if cc:
                print(source_type.upper(), "country code:", cc)
                cn = self.get_name_from_country_code(cc)
                if cn:
                    print(source_type.upper(), "country name:", cn)

    def lookup_ipv4_address(self, lookup_ipaddr):
        print("Reverse lookup for: " + str(lookup_ipaddr))
        maxmind_cc = self.database_cache.fetch_country_code('ipv4', 'maxmind',
                                                            int(lookup_ipaddr))
        if maxmind_cc:
            print('MaxMind country code:', maxmind_cc)
            maxmind_cn = self.get_name_from_country_code(maxmind_cc)
            if maxmind_cn:
                print('MaxMind country name:', maxmind_cn)
        rir_cc = self.database_cache.fetch_country_code('ipv4', 'rir',
                                                        int(lookup_ipaddr))
        if rir_cc:
            print('RIR country code:', rir_cc)
            rir_cn = self.get_name_from_country_code(rir_cc)
            if rir_cn:
                print('RIR country name:', rir_cn)
        else:
            print('Not found in RIR db')
        lir_cc = self.database_cache.fetch_country_code('ipv4', 'lir',
                                                        int(lookup_ipaddr))
        if lir_cc:
            print('LIR country code:', lir_cc)
            lir_cn = self.get_name_from_country_code(lir_cc)
            if lir_cn:
                print('LIR country name:', lir_cn)
        if maxmind_cc and maxmind_cc != rir_cc:
            print("It appears that the RIR data conflicts with MaxMind's "
                  "data.  MaxMind's data is likely closer to being "
                  "correct due to sub-delegation issues with LIR databases.")

    def lookup_ip_address(self, lookup_str):
        """ Return the country code and name for a given ip address. """
        try:
            lookup_ipaddr = ipaddr.ip_address(lookup_str)
            if isinstance(lookup_ipaddr, ipaddr.IPv4Address):
                self.lookup_ipv4_address(lookup_ipaddr)
            elif isinstance(lookup_ipaddr, ipaddr.IPv6Address):
                self.lookup_ipv6_address(lookup_ipaddr)
            else:
                print(("Did not recognize '%s' as either IPv4 or IPv6 "
                       "address." % lookup_str))
        except ValueError as e:
            print("'%s' is not a valid IP address." % lookup_str)

    def asn_lookup(self, asn):
        asn_cc = self.database_cache.fetch_country_code('asn', 'rir', asn)
        if asn_cc:
            print("AS country code: %s" % asn_cc)
            asn_cn = self.get_name_from_country_code(asn_cc)
            if asn_cn:
                print("AS country name: %s" % asn_cn)
        else:
            print("AS%s not found!" % asn)

    def fetch_rir_blocks_by_country(self, request, country):
        if request == "asn":
            return [str(start_num) for (start_num, end_num) in
                    self.database_cache.fetch_assignments(request, country)]
        if request != "ipv4" and request != "ipv6":
            return []
        seen = set()
        result = []
        for (start_num, end_num) in \
                self.database_cache.fetch_assignments(request, country):
            start_ipaddr = ipaddr.ip_address(start_num)
            end_ipaddr = ipaddr.ip_address(end_num)
            for block in (str(x) for x in
                          ipaddr.summarize_address_range(start_ipaddr,
                                                         end_ipaddr)):
                if block in seen:
                    continue
                seen.add(block)
                result.append(block)
        return result

    def lookup_countries_in_different_source(self, first_country_code):
        """ Look up all assignments matching the given country code, then
            look up to which country code(s) the same number ranges are
            assigned in other source types.  Print out the result showing
            similarities and differences. """
        print(("\nLegend:\n"
               "  '<' = found assignment range with country code '%s'\n"
               "  '>' = overlapping assignment range with same country code\n"
               "  '*' = overlapping assignment range, first conflict\n"
               "  '#' = overlapping assignment range, second conflict and "
               "beyond\n  ' ' = neighboring assignment range") % (
            first_country_code, ))
        results = self.database_cache.fetch_country_blocks_in_other_sources(
            first_country_code)
        prev_first_source_type = ''
        prev_first_start_num = -1
        cur_second_country_codes = []
        for (first_source_type, first_start_num, first_end_num,
                second_source_type, second_start_num, second_end_num,
                second_country_code, num_type) in results:
            if first_source_type != prev_first_source_type:
                print("\nAssignments in '%s':" % (first_source_type, ))
            prev_first_source_type = first_source_type
            if first_start_num != prev_first_start_num:
                cur_second_country_codes = []
                print("")
            prev_first_start_num = first_start_num
            marker = ''
            if second_end_num >= first_start_num and \
                    second_start_num <= first_end_num:
                if first_country_code != second_country_code and \
                        second_country_code not in cur_second_country_codes:
                    cur_second_country_codes.append(second_country_code)
                if first_source_type == second_source_type:
                    marker = '<'
                elif len(cur_second_country_codes) == 0:
                    marker = '>'
                elif len(cur_second_country_codes) == 1:
                    marker = '*'
                else:
                    marker = '#'
            if num_type.startswith("ip") and \
                    second_start_num == second_end_num:
                second_range = "%s" % (ipaddr.ip_address(second_start_num), )
            elif num_type.startswith("ip") and \
                    second_start_num < second_end_num:
                second_range = "%s-%s" % (ipaddr.ip_address(second_start_num),
                                          ipaddr.ip_address(second_end_num))
            elif second_start_num < second_end_num:
                second_range = "AS%d-%d" % (second_start_num, second_end_num)
            else:
                second_range = "AS%d" % (second_start_num, )
            print("%1s %s %s %s" % (marker, second_country_code, second_range,
                                    second_source_type, ))

    def _get_network_string_from_range(self, end, start, bits=32):
        start, end = int(start, 16), int(end, 16)
        netbits = bits - int(log(end - start, 2))
        return ipaddr.IPNetwork("%s/%d" % (ipaddr.IPAddress(start), netbits))

    def lookup_org_by_ip(self, lookup_str):
        """ Return the ASN and AS Description by IP """
        try:
            lookup_ipaddr = ipaddr.IPAddress(lookup_str)
            if isinstance(lookup_ipaddr, ipaddr.IPv4Address):
                num_type = 'ipv4'
                len_bits = 32
            elif isinstance(lookup_ipaddr, ipaddr.IPv6Address):
                num_type = 'ipv6'
                len_bits = 128
            else:
                raise ValueError
            rs = self.database_cache.fetch_org_by_ip_address(
                lookup_ipaddr, num_type)
            for r in rs:
                network = self._get_network_string_from_range(
                    r[3], r[2], bits=len_bits)
                print("%s in %s announced by AS%s - %s" %
                      (lookup_str, network, r[0], r[1]))
        except ValueError:
            print("'%s' is not a valid IP address." % lookup_str)
        except TypeError:
            print("Did not find any matching announcements containing %s." %
                  lookup_str)

    def lookup_org_by_range(self, start_range, end_range):
        output_str = "%s announced by AS%s - %s"
        try:
            a = ipaddr.IPAddress(start_range)
            b = ipaddr.IPAddress(end_range)
            if isinstance(a, ipaddr.IPv4Address) and isinstance(
                    b, ipaddr.IPv4Address):
                num_type = 'ipv4'
                len_bits = 32
            elif isinstance(a, ipaddr.IPv6Address) and (
                    isinstance(b, ipaddr.IPv6Address)):
                num_type = 'ipv6'
                len_bits = 128
            else:
                raise ValueError
            rs = self.database_cache.fetch_org_by_ip_range(
                min(a, b), max(a, b), num_type)
            for r in rs:
                network = self._get_network_string_from_range(
                    r[3], r[2], bits=len_bits)
                print(output_str % (network, r[0], r[1]))
        except ValueError:
            print("%s %s is not a valid IP range." % (start_range, end_range))
        except TypeError:
            print("Did not find any matching announcements in range %s %s." %
                  (start_range, end_range))


def split_callback(option, opt, value, parser):
    split_value = value.split(':')
    setattr(parser.values, option.dest, split_value[0])
    if len(split_value) > 1 and split_value[1] != '':
        setattr(parser.values, 'type_filter', split_value[1])


def normalize_country_code(country_code):
    """ Normalize country codes a bit by making capitalization consistent and
        removing trailing comments (and other words). """
    if not country_code:
        return country_code
    country_code = re.match(r'^(\w+)', country_code).group(1)
    return country_code.upper()


def main():
    """ Where the magic starts. """
    usage = ("Usage: %prog [options]\n\n"
             "Example: %prog -v -t mm")
    parser = optparse.OptionParser(usage)
    parser.add_option("-v", "--verbose", action="store_true",
                      dest="verbose", help="be verbose", default=False)
    parser.add_option("-c", "--cache-dir", action="store", dest="dir",
                      help="set cache directory [default: %default]",
                      default=str(os.path.expanduser('~')) + "/.blockfinder/")
    parser.add_option("--user-agent", action="store", dest="ua",
                      help=('provide a User-Agent which will be used when '
                            'fetching delegation files [default: "%default"]'),
                      default=("Mozilla/5.0 (Windows NT 6.1; rv:17.0) "
                               "Gecko/20100101 Firefox/17.0"))
    parser.add_option("-x", "--hack-the-internet", action="store_true",
                      dest="hack_the_internet", help=optparse.SUPPRESS_HELP)
    group = optparse.OptionGroup(
        parser,
        "Cache modes",
        "Pick at most one of these modes to initialize or update "
        "the local cache.  May not be combined with lookup modes.")
    group.add_option(
        "-m",
        "--init-maxmind",
        action="store_true",
        dest="init_maxmind",
        help="initialize or update MaxMind GeoIP database")
    group.add_option(
        "-g",
        "--reload-maxmind",
        action="store_true",
        dest="reload_maxmind",
        help=("update cache from existing MaxMind GeoIP database"))
    group.add_option(
        "-r",
        "--import-maxmind",
        action="store",
        dest="import_maxmind",
        metavar="FILE",
        help=("import the specified MaxMind GeoIP database file into "
              "the database cache using its file name as source "
              "name"))
    group.add_option("-i", "--init-rir",
                     action="store_true", dest="init_del",
                     help="initialize or update delegation information")
    group.add_option(
        "-d",
        "--reload-rir",
        action="store_true",
        dest="reload_del",
        help="use existing delegation files to update the database")
    group.add_option(
        "-l",
        "--init-lir",
        action="store_true",
        dest="init_lir",
        help=("initialize or update lir information; can take up to "
              "5 minutes"))
    group.add_option(
        "-z",
        "--reload-lir",
        action="store_true",
        dest="reload_lir",
        help=("use existing lir files to update the database; can "
              "take up to 5 minutes"))
    group.add_option(
        "-o",
        "--download-cc",
        action="store_true",
        dest="download_cc",
        help="download country codes file")
    group.add_option(
        "-e",
        "--erase-cache",
        action="store_true",
        dest="erase_cache",
        help="erase the local database cache")
    group.add_option(
        "-j",
        "--init-asn-descriptions",
        action="store_true",
        dest="init_asn_descriptions",
        help=("initialize or update asn description information"))
    group.add_option(
        "-k",
        "--reload-asn-descriptions",
        action="store_true",
        dest="reload_asn_descriptions",
        help=("Use existing asn descriptions to update database"))
    group.add_option(
        "-y",
        "--init-asn-assignments",
        action="store_true",
        dest="init_asn_assignments",
        help=("initialize or update asn assignment information"))
    group.add_option(
        "-u",
        "--reload-asn-assignments",
        action="store_true",
        dest="reload_asn_assignments",
        help=("Use existing asn assignments to update database"))
    parser.add_option_group(group)
    group = optparse.OptionGroup(
        parser, "Lookup modes",
        "Pick at most one of these modes to look up data in the "
        "local cache.  May not be combined with cache modes.")
    group.add_option(
        "-4",
        "--ipv4",
        action="store",
        dest="ipv4",
        help=("look up country code and name for the specified IPv4 "
              "address"))
    group.add_option(
        "-6",
        "--ipv6",
        action="store",
        dest="ipv6",
        help=("look up country code and name for the specified IPv6 "
              "address"))
    group.add_option(
        "-a",
        "--asn",
        action="store",
        dest="asn",
        help="look up country code and name for the specified ASN")
    group.add_option(
        "-t",
        "--code",
        action="callback",
        dest="cc",
        callback=split_callback,
        metavar="CC[:type]",
        type="str",
        help=("look up all allocations (or only those for number "
              "type 'ipv4', 'ipv6', or 'asn' if provided) in the "
              "delegation cache for the specified two-letter country "
              "code"))
    group.add_option(
        "-n",
        "--name",
        action="callback",
        dest="cn",
        callback=split_callback,
        metavar="CN[:type]",
        type="str",
        help=("look up all allocations (or only those for number "
              "type 'ipv4', 'ipv6', or 'asn' if provided) in the "
              "delegation cache for the specified full country "
              "name"))
    group.add_option(
        "-p",
        "--compare",
        action="store",
        dest="compare",
        metavar="CC",
        help=("compare assignments to the specified country code "
              "with overlapping assignments in other data "
              "sources; can take some time and produce some "
              "long output"))
    group.add_option(
        "-w",
        "--what-country",
        action="store",
        dest="what_cc",
        help=("look up country name for specified country code"))
    group.add_option(
        "--lookup-org-by-ip",
        "--lookup-org-by-ip",
        action="store",
        dest="lookup_org_by_ip",
        help=("look up ASN and AS Description for an IP address"))
    group.add_option(
        "--lookup-org-by-range",
        "--lookup-org-by-range",
        action="store_true",
        dest="lookup_org_by_range",
        help=("look up announced networks in a range of addresses; "
              "requires --range-start and --range-end to be set"))
    group.add_option(
        "--range-start",
        "--range-start",
        action="store",
        dest="range_start",
        help=("Specify the start of a range of addresses"))
    group.add_option(
        "--range-end", "--range-end",
        action="store",
        dest="range_end",
        help=("Specify the end of a range of addresses"))
    parser.add_option_group(group)
    group = optparse.OptionGroup(parser, "Export modes")
    group.add_option(
        "--export-geoip",
        "--export-geoip",
        action="store_true",
        dest="export",
        help=("export the lookup database to GeoIPCountryWhois.csv and "
              "v6.csv files in the format used to build the debian "
              "package geoip-database"))
    group.add_option(
        "--geoip-v4-file",
        "--geoip-v4-file",
        action="store",
        dest="geoip_v4_filename",
        help=("The filename to write the IPv4 GeoIP dataset to"))
    group.add_option(
        "--geoip-v6-file",
        "--geoip-v6-file",
        action="store",
        dest="geoip_v6_filename",
        help=("The filename to write the IPv6 GeoIP dataset to"))
    group.add_option(
        "--geoip-asn-file",
        "--geoip-asn-file",
        action="store",
        dest="geoip_asn_filename",
        help=("The filename to write the IPv4 GeoIP ASNum dataset to"))
    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, "Network modes")
    (options, args) = parser.parse_args()
    if options.hack_the_internet:
        print("all your bases are belong to us!")
        sys.exit(0)
    options_dict = vars(options)
    modes = 0
    for mode in ["init_maxmind", "reload_maxmind", "import_maxmind",
                 "init_del", "init_lir", "reload_del", "reload_lir",
                 "download_cc", "erase_cache", "ipv4", "ipv6", "asn",
                 "cc", "cn", "compare", "what_cc", "init_asn_descriptions",
                 "reload_asn_descriptions", "init_asn_assignments",
                 "reload_asn_assignments", "lookup_org_by_ip",
                 "lookup_org_by_range", "export"]:
        if mode in options_dict and options_dict.get(mode):
            modes += 1
    if modes > 1:
        parser.error("only 1 cache or lookup mode allowed")
    elif modes == 0:
        parser.error("must provide 1 cache or lookup mode")
    database_cache = DatabaseCache(options.dir, options.verbose)
    if options.erase_cache:
        database_cache.erase_database()
        sys.exit(0)
    if not database_cache.connect_to_database():
        print("Could not connect to database.")
        print("You may need to erase it using -e and then reload it "
              "using -d/-z.  Exiting.")
        sys.exit(1)
    database_cache.set_db_version()
    downloader_parser = DownloaderParser(options.dir, database_cache,
                                         options.ua)
    lookup = Lookup(options.dir, database_cache)
    if options.ipv4 or options.ipv6 or options.asn or options.cc \
            or options.cn or options.compare:
        if downloader_parser.check_rir_file_mtimes():
            print("Your cached RIR files are older than 24 hours; you "
                  "probably want to update them.")
    if options.asn:
        lookup.asn_lookup(options.asn)
    elif options.lookup_org_by_ip:
        lookup.lookup_org_by_ip(options.lookup_org_by_ip)
    elif options.lookup_org_by_range:
        if not (options.range_start and options.range_end):
            print("You must specify the start and end addresses; "
                  "see --range-start and --range-end")
        else:
            lookup.lookup_org_by_range(options.range_start, options.range_end)
    elif options.ipv4:
        lookup.lookup_ip_address(options.ipv4)
    elif options.ipv6:
        lookup.lookup_ip_address(options.ipv6)
    elif options.cc or options.cn or options.what_cc:
        country = None
        if options.cc:
            country = options.cc.upper()
        elif not lookup.knows_country_names():
            print("Need to download country codes first before looking "
                  "up countries by name.")
        elif options.what_cc:
            country = options.what_cc.upper()
            country_name = lookup.get_name_from_country_code(country)
            if country_name:
                print(("Hmm...%s? That would be %s."
                       % (options.what_cc, country_name)))
                sys.exit(0)
            else:
                print(("Hmm, %s? We're not sure either. Are you sure that's "
                       "a country code?" % options.what_cc))
                sys.exit(1)
        else:
            country = lookup.get_country_code_from_name(options.cn)
            if not country:
                print("It appears your search did not match a country.")
        if country:
            types = ["ipv4", "ipv6", "asn"]
            if hasattr(options, 'type_filter') and \
                    options.type_filter.lower() in types:
                types = [options.type_filter.lower()]
            for request in types:
                print("\n".join(lookup.fetch_rir_blocks_by_country(
                    request, country)))
    elif options.compare:
        print("Comparing assignments with overlapping assignments in other "
              "data sources...")
        lookup.lookup_countries_in_different_source(options.compare)
    elif options.init_maxmind or options.reload_maxmind:
        if options.init_maxmind:
            print("Downloading Maxmind GeoIP files...")
            downloader_parser.download_maxmind_files()
        print("Importing Maxmind GeoIP files...")
        downloader_parser.parse_maxmind_files()
    elif options.import_maxmind:
        print("Importing Maxmind GeoIP files...")
        downloader_parser.import_maxmind_file(options.import_maxmind)
    elif options.init_del or options.reload_del:
        if options.init_del:
            print("Downloading RIR files...")
            downloader_parser.download_rir_files()
            print("Verifying RIR files...")
            downloader_parser.verify_rir_files()
        print("Importing RIR files...")
        downloader_parser.parse_rir_files()
    elif options.init_lir or options.reload_lir:
        if options.init_lir:
            print("Downloading LIR delegation files...")
            downloader_parser.download_lir_files()
        print("Importing LIR files...")
        downloader_parser.parse_lir_files()
    elif options.download_cc:
        print("Downloading country code file...")
        downloader_parser.download_country_code_file()
    elif options.init_asn_descriptions or options.reload_asn_descriptions:
        if options.init_asn_descriptions:
            print("Downloading ASN Descriptions...")
            downloader_parser.download_asn_description_file()
        print("Importing ASN Descriptions...")
        downloader_parser.parse_asn_description_file()
    elif options.init_asn_assignments or options.reload_asn_assignments:
        if options.init_asn_assignments:
            print("Downloading ASN Assignments...")
            downloader_parser.download_asn_assignment_files()
        print("Importing ASN Assignments...")
        downloader_parser.parse_asn_assignment_files()
    elif options.export:
        v4_file = options.geoip_v4_filename or "GeoIPCountryWhois.csv"
        v6_file = options.geoip_v6_filename or "v6.csv"
        asn_file = options.geoip_asn_filename or "GeoIPASNum.csv"
        print("Exporting GeoIP IPv4 to %s" % v4_file)
        database_cache.export_geoip(lookup, v4_file, 'ipv4')
        print("Exporting GeoIP IPv6 to %s" % v6_file)
        database_cache.export_geoip(lookup, v6_file, 'ipv6')
        print("Exporting GeoIP IPv4 ASNum to %s" % asn_file)
        database_cache.export_asn(asn_file, 'ipv4')
        # XXX: Unsupported
        # print("Exporting GeoIP IPv6 ASNum to %s" % asn_file)
        # database_cache.export_geoip(asn_file, 'ipv6')
    database_cache.commit_and_close_database()

if __name__ == "__main__":
    main()
