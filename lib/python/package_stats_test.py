#!/usr/bin/env python2.6

import unittest
import package_stats

LDD_R_OUTPUT_1 =  """\tlibc.so.1 =>  /lib/libc.so.1
\tsymbol not found: check_encoding_conversion_args    (/opt/csw/lib/postgresql/8.4/utf8_and_gbk.so)
\tsymbol not found: LocalToUtf    (/opt/csw/lib/postgresql/8.4/utf8_and_gbk.so)
\tsymbol not found: UtfToLocal    (/opt/csw/lib/postgresql/8.4/utf8_and_gbk.so)
\tlibm.so.2 =>   /lib/libm.so.2
\t/usr/lib/secure/s8_preload.so.1
\tlibXext.so.0 (SUNW_1.1) =>\t (version not found)
\trelocation R_SPARC_COPY symbol: ASN1_OCTET_STRING_it: file /opt/csw/lib/sparcv8plus+vis/libcrypto.so.0.9.8: relocation bound to a symbol with STV_PROTECTED visibility
\trelocation R_SPARC_COPY sizes differ: _ZTI7QWidget
\t\t(file /tmp/pkg_GqCk0P/CSWkdeartworkgcc/root/opt/csw/kde-gcc/bin/kslideshow.kss size=0x28; file /opt/csw/kde-gcc/lib/libqt-mt.so.3 size=0x20)
"""

class PackageStatsUnitTest(unittest.TestCase):

  def setUp(self):
    self.pkgstats = package_stats.PackageStats(None)

  def test_ParseNmSymLineGoodLine(self):
    line = '0000097616 T aliases_lookup'
    expected = {
        'address': '0000097616',
        'type': 'T',
        'name': 'aliases_lookup',
    }
    self.assertEqual(expected, self.pkgstats._ParseNmSymLine(line))

  def test_ParseNmSymLineBadLine(self):
    line = 'foo'
    self.assertEqual(None, self.pkgstats._ParseNmSymLine(line))

  def test_ParseLddDashRlineFound(self):
    line = '\tlibc.so.1 =>  /lib/libc.so.1'
    expected = {
        'state': 'OK',
        'soname': 'libc.so.1',
        'path': '/lib/libc.so.1',
        'symbol': None,
    }
    self.assertEqual(expected, self.pkgstats._ParseLddDashRline(line))

  def test_ParseLddDashRlineSymbolMissing(self):
    line = ('\tsymbol not found: check_encoding_conversion_args    '
            '(/opt/csw/lib/postgresql/8.4/utf8_and_gbk.so)')
    expected = {
        'state': 'symbol-not-found',
        'soname': None,
        'path': '/opt/csw/lib/postgresql/8.4/utf8_and_gbk.so',
        'symbol': 'check_encoding_conversion_args',
    }
    self.assertEqual(expected, self.pkgstats._ParseLddDashRline(line))

  def test_ParseLddDashRlineFound(self):
    line = '\t/usr/lib/secure/s8_preload.so.1'
    expected = {
        'state': 'OK',
        'soname': None,
        'path': '/usr/lib/secure/s8_preload.so.1',
        'symbol': None,
    }
    self.assertEqual(expected, self.pkgstats._ParseLddDashRline(line))

  def test_ParseLdd_VersionNotFound(self):
    line = '\tlibXext.so.0 (SUNW_1.1) =>\t (version not found)'
    expected = {
        'symbol': None,
        'soname': 'libXext.so.0',
        'path': None,
        'state': 'version-not-found',
    }
    self.assertEqual(expected, self.pkgstats._ParseLddDashRline(line))

  def test_ParseLdd_StvProtectedVisibility(self):
    line = ('\trelocation R_SPARC_COPY symbol: ASN1_OCTET_STRING_it: '
            'file /opt/csw/lib/sparcv8plus+vis/libcrypto.so.0.9.8: '
            'relocation bound to a symbol with STV_PROTECTED visibility')
    expected = {
        'symbol': 'ASN1_OCTET_STRING_it',
        'soname': None,
        'path': '/opt/csw/lib/sparcv8plus+vis/libcrypto.so.0.9.8',
        'state': 'relocation-bound-to-a-symbol-with-STV_PROTECTED-visibility',
    }
    self.assertEqual(expected, self.pkgstats._ParseLddDashRline(line))

  def test_ParseLdd_SizesDiffer(self):
    line = '\trelocation R_SPARC_COPY sizes differ: _ZTI7QWidget'
    expected = {
        'symbol': '_ZTI7QWidget',
        'soname': None,
        'path': None,
        'state': 'sizes-differ',
    }
    self.assertEqual(expected, self.pkgstats._ParseLddDashRline(line))

  def test_ParseLdd_SizesDifferInfo(self):
    line = ('\t\t(file /tmp/pkg_GqCk0P/CSWkdeartworkgcc/root/opt/csw/kde-gcc/bin/'
            'kslideshow.kss size=0x28; '
            'file /opt/csw/kde-gcc/lib/libqt-mt.so.3 size=0x20)')
    expected = {
        'symbol': None,
        'path': ('/tmp/pkg_GqCk0P/CSWkdeartworkgcc/root/opt/csw/kde-gcc/'
                 'bin/kslideshow.kss /opt/csw/kde-gcc/lib/libqt-mt.so.3'),
        'state': 'sizes-diff-info',
        'soname': None,
    }
    self.assertEqual(expected, self.pkgstats._ParseLddDashRline(line))

  def test_ParseLdd_SizesDifferOneUsed(self):
    line = ('\t\t/opt/csw/kde-gcc/lib/libqt-mt.so.3 size used; '
            'possible insufficient data copied')
    expected = {
        'symbol': None,
        'path': '/opt/csw/kde-gcc/lib/libqt-mt.so.3',
        'state': 'sizes-diff-one-used',
        'soname': None,
    }
    self.assertEqual(expected, self.pkgstats._ParseLddDashRline(line))

  def test_ParseLddDashRlineManyLines(self):
    for line in LDD_R_OUTPUT_1.splitlines():
      parsed = self.pkgstats._ParseLddDashRline(line)


