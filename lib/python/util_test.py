#!/opt/csw/bin/python2.6

import unittest2 as unittest
import mox
import os

from lib.python import util
from lib.python import shell
from lib.python import common_constants
from lib.python import representations


DUMP_OUTPUT = '''
  **** DYNAMIC SECTION INFORMATION ****
.dynamic:
[INDEX] Tag         Value
[1]     NEEDED          libXext.so.0
[2]     NEEDED          libX11.so.4
[3]     NEEDED          libsocket.so.1
[4]     NEEDED          libnsl.so.1
[5]     NEEDED          libc.so.1
[6]     INIT            0x80531e4
[7]     FINI            0x8053200
[8]     HASH            0x80500e8
[9]     STRTAB          0x8050cb0
[10]    STRSZ           0x511
[11]    SYMTAB          0x80504e0
[12]    SYMENT          0x10
[13]    CHECKSUM        0x9e8
[14]    VERNEED         0x80511c4
[15]    VERNEEDNUM      0x2
[16]    PLTSZ           0x1a0
[17]    PLTREL          0x11
[18]    JMPREL          0x8051224
[19]    REL             0x8051214
[20]    RELSZ           0x1b0
[21]    RELENT          0x8
[22]    DEBUG           0
[23]    FEATURE_1       PARINIT
[24]    FLAGS           0
[25]    FLAGS_1         0
[26]    PLTGOT          0x806359c
'''

BINARY_DUMP_INFO = {
  'base_name': 'foo',
  'RUNPATH RPATH the same': True,
  'runpath': (),
  'RPATH set': False,
  'needed sonames': (
    'libXext.so.0',
    'libX11.so.4',
    'libsocket.so.1',
    'libnsl.so.1',
    'libc.so.1'),
  'path': 'opt/csw/bin/foo',
  'RUNPATH set': False,
  }

BINARY_DUMP_INFO = (
    representations.BinaryDumpInfo(
      path='opt/csw/bin/foo', base_name='foo', soname=None,
      needed_sonames=('libXext.so.0', 'libX11.so.4', 'libsocket.so.1',
                      'libnsl.so.1', 'libc.so.1'),
      runpath=(), runpath_rpath_the_same=True, rpath_set=False,
      runpath_set=False)
)


class BinaryDumpUnitTest(mox.MoxTestBase, unittest.TestCase):

  def testGetBinaryDumpInfoRoot(self):
    fake_binaries = [
        ('opt/csw/bin/foo', 'foo', '/tmp/base/opt/csw/bin/foo'),
    ]

    self.mox.StubOutWithMock(shell, 'ShellCommand')
    args = [common_constants.DUMP_BIN,
            '-Lv',
            os.path.join('/tmp/base', fake_binaries[0][0])]
    shell.ShellCommand(args, mox.IgnoreArg()).AndReturn((0, DUMP_OUTPUT, ""))
    self.mox.ReplayAll()

    self.assertEqual([BINARY_DUMP_INFO],
        util.GetBinariesDumpInfo(fake_binaries))


if __name__ == '__main__':
  unittest.main()
