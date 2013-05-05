import unittest2 as unittest

BINARY_ELFINFO = {
    'opt/csw/lib/libssl.so.1.0.0': {
      'symbol table': [
        {'shndx': 'UNDEF', 'soname': None, 'bind': 'LOCL',
          'symbol': None, 'version': None, 'flags': None, 'type': 'NOTY'},
        {'shndx': 'UNDEF', 'soname': 'libcrypto.so.1.0.0', 'bind': 'GLOB',
          'symbol': 'EVP_DigestSignFinal', 'version': 'OPENSSL_1.0.0',
          'flags': 'DBL', 'type': 'FUNC'},
        {'shndx': 'UNDEF', 'soname': 'libcrypto.so.1.0.0', 'bind': 'GLOB',
          'symbol': 'SRP_Calc_client_key', 'version': 'OPENSSL_1.0.1',
          'flags': 'DBL', 'type': 'FUNC'},
        {'shndx': '.text', 'soname': None, 'bind': 'GLOB',
          'symbol': 'SSL_CTX_set_srp_client_pwd_callback',
          'version': 'OPENSSL_1.0.1', 'flags': 'DB', 'type': 'FUNC'},
        {'shndx': '.text', 'soname': None, 'bind': 'GLOB',
          'symbol': 'SSL_get_shared_ciphers', 'version': 'OPENSSL_1.0.0',
          'flags': 'DB', 'type': 'FUNC'},
        {'shndx': '.got', 'soname': None, 'bind': 'GLOB',
          'symbol': '_GLOBAL_OFFSET_TABLE_', 'version': None,
          'flags': 'DB', 'type': 'OBJT'},
        ],
      'version definition': [
        {'dependency': None, 'version': 'OPENSSL_1.0.0'},
        {'dependency': 'OPENSSL_1.0.0', 'version': 'OPENSSL_1.0.1'},
        ],
      'version needed': [
        {'version': 'OPENSSL_1.0.0', 'soname': 'libcrypto.so.1.0.0'},
        {'version': 'OPENSSL_1.0.1', 'soname': 'libcrypto.so.1.0.0'},
        {'version': 'SUNW_1.9.1', 'soname': 'libnsl.so.1'},
      ]
    }
}



class PackageStatsUnitTest(unittest.TestCase):

  def setUp(self):
    self.ip = inspective_package.InspectivePackage("/fake/path/CSWfoo")

  def test_ParseElfdumpLineSectionHeader(self):
    line = 'Symbol Table Section:  .dynsym'
    self.assertEqual((None, "symbol table"), self.ip._ParseElfdumpLine(line, None))

  def test_ParseElfdumpLineVersionNeeded(self):
    line = '[13]                              SUNW_0.9             [ INFO ]'
    expected = {
      'index': '13',
      'version': 'SUNW_0.9',
      'soname': None
    }
    self.assertEqual((expected, "version needed"), self.ip._ParseElfdumpLine(line, 'version needed'))

  def test_ParseElfdumpLineSymbolTable(self):
    line = '    [9]  0x000224b8 0x0000001c  FUNC GLOB  D    1 .text          vsf_log_line'
    expected = {
      'bind': 'GLOB',
      'shndx': '.text',
      'symbol': 'vsf_log_line',
      'version': '1',
      'type': 'FUNC',
    }
    self.assertEqual((expected, 'symbol table'), self.ip._ParseElfdumpLine(line, 'symbol table'))

  def test_ParseElfdumpLineNeededSymbol(self):
    line = '      [152]  DB           [4] libc.so.1                strlen'
    expected = {
        'flags': 'DB',
        'soname': 'libc.so.1',
        'symbol': 'strlen',
    }
    self.assertEqual((expected, "syminfo"), self.ip._ParseElfdumpLine(line, "syminfo"))

  def test_ParseElfdumpLineExportedSymbol(self):
    line = '      [116]  DB               <self>                   environ'
    expected = {
        'flags': 'DB',
        'soname': None,
        'symbol': 'environ',
    }
    self.assertEqual((expected, "syminfo"), self.ip._ParseElfdumpLine(line, "syminfo"))


