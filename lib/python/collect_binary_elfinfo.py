#!/opt/csw/bin/python2.6

import hashlib
import io
import json
import logging
import mmap
import optparse
import os
import re
import sys
import tempfile

from lib.python import common_constants
from lib.python import configuration
from lib.python import errors
from lib.python import rest
from lib.python import shell

class ElfExtractor(object):

  def __init__(self, binary_path, debug):
    self.debug = debug
    self._binary_path = binary_path
    self.config = configuration.GetConfig()
    self.rest_client = rest.RestClient(
        pkgdb_url=self.config.get('rest', 'pkgdb'),
        releases_url=self.config.get('rest', 'releases'))

  def CollectBinaryElfinfo(self):
    """Returns various informations symbol and versions present in elf header

    To do this we parse output lines from elfdump -syv, it's the
    only command that will give us all informations we need on
    symbols and versions.

    We will analyse 3 sections:
     - version section: contains soname needed, version interface required
                        for each soname, and version definition
     - symbol table section: contains list of symbol and soname/version
                             interface providing it
     - syminfo section: contains special linking flags for each symbol

    The amount of data is too large for it to fit in memory at one time,
    therefore the rest_client is passed to facilitate saving data.
    """
    binary_abspath = self._binary_path
    md5_hash = hashlib.md5()
    with open(binary_abspath, 'rb') as fd:
      md5_hash.update(fd.read())
    md5_sum = md5_hash.hexdigest()
    if self.rest_client.BlobExists('elfdump', md5_sum):
      logging.debug('We already have info about %r.', binary_abspath)
      return md5_sum
    # elfdump is the only tool that give us all informations
    elfdump_output_file = tempfile.TemporaryFile()
    args = [common_constants.ELFDUMP_BIN, "-svy", binary_abspath]
    retcode, stdout, stderr = shell.ShellCommand(args, allow_error=True,
                                                 stdout=elfdump_output_file)
    if retcode or stderr:
      # we ignore for now these elfdump errors which can be catched
      # later by check functions,
      ignored_error_re = re.compile(
        r"""[^:]+:(\s\.((SUNW_l)?dynsym|symtab):\s
         ((index\[\d+\]:\s)?
          (suspicious\s(local|global)\ssymbol\sentry:\s[^:]+:\slies
           \swithin\s(local|global)\ssymbol\srange\s\(index\s[<>=]+\s\d+\)

          |bad\ssymbol\sentry:\s[^:]+:\ssection\[\d+\]\ssize:\s0(x[0-9a-f]+)?
           :\s(symbol\s\(address\s0x[0-9a-f]+,\ssize\s0x[0-9a-f]+\)
               \slies\soutside\sof\scontaining\ssection
               |is\ssmaller\sthan\ssymbol\ssize:\s\d+)

          |bad\ssymbol\sentry:\s:\sinvalid\sshndx:\s\d+
          |)

         |invalid\ssh_link:\s0)

         |\smemory\soverlap\sbetween\ssection\[\d+\]:\s[^:]+:\s
          [0-9a-f]+:[0-9a-f]+\sand\ssection\[\d+\]:\s[^:]+:
          \s[0-9a-f]+:[0-9a-f]+)
         \n""",
        re.VERBOSE)

      stderr = re.sub(ignored_error_re, "", stderr)
      if stderr:
        with open("/tmp/elfdump_stdout.log", "w") as fd:
          fd.write(stdout)
        with open("/tmp/elfdump_stderr.log", "w") as fd:
          fd.write(stderr)
        msg = ("%s returned one or more errors: %s" % (args, stderr) +
               "\n\n" +
               "ERROR: elfdump invocation failed. Please copy this message " +
               "and the above messages into your report and send " +
               "as path of the error report. Logs are saved in " +
               "/tmp/elfdump_std(out|err).log for your inspection.")
        raise errors.Error(msg)

    symbols = {}
    binary_info = {'version definition': [],
                   'version needed': []}

    # A special case for an empty file: mmap + empty file doesn't work.
    try:
      file_size = os.fstat(elfdump_output_file.fileno()).st_size
    except io.UnsupportedOperation:
      file_size = len(elfdump_output_file.getvalue())
    if not file_size:
      binary_info['symbol table'] = []
      self.rest_client.SaveBlob('elfdump', md5_sum, binary_info)
      return md5_sum

    try:
      fileno = elfdump_output_file.fileno()
      elfdump_output = mmap.mmap(fileno, 0, prot=mmap.PROT_READ)
    except io.UnsupportedOperation:
      elfdump_output = elfdump_output_file


    cur_section = None
    for line in iter(elfdump_output.readline, ""):
      try:
        elf_info, cur_section = self._ParseElfdumpLine(line, cur_section)
      except errors.StdoutSyntaxError as e:
        sys.stderr.write("elfdump out:\n")
        sys.stderr.write(stdout)
        raise

      # header or blank line contains no information
      if not elf_info:
        continue

      # symbol table and syminfo section store various informations
      # about the same symbols, so we merge them in a dict
      if cur_section in ('symbol table', 'syminfo'):
        symbols.setdefault(elf_info['symbol'], {}).update(elf_info)
      else:
        binary_info[cur_section].append(elf_info)

    # elfdump doesn't repeat the name of the soname in the version section
    # if it's the same on two contiguous line, e.g.:
    #         libc.so.1            SUNW_1.1
    #                              SUNWprivate_1.1
    # so we have to make sure the information is present in each entry
    for i, version in enumerate(binary_info['version needed'][1:]):
      if not version['soname']:
        version['soname'] = binary_info['version needed'][i]['soname']

    # soname version needed are usually displayed sorted by index ...
    # but that's not always the case :( so we have to reorder
    # the list by index if they are present
    if any ( v['index'] for v in binary_info['version needed'] ):
      binary_info['version needed'].sort(key=lambda m: int(m['index']))
      for version in binary_info['version needed']:
        del version['index']

    # if it exists, the first "version definition" entry is the base soname
    # we don't need this information
    if binary_info['version definition']:
      binary_info['version definition'].pop(0)

    binary_info['symbol table'] = symbols.values()
    binary_info['symbol table'].sort(key=lambda m: m['symbol'])
    # To not rely of the section order output of elfdump, we resolve
    # symbol version informations here after having parsed all output
    self._ResolveSymbolsVersionInfo(binary_info)

    self.rest_client.SaveBlob('elfdump', md5_sum, binary_info)
    return md5_sum

  def _ResolveSymbolsVersionInfo(self, binary_info):
    version_info = (binary_info['version definition']
                    + binary_info['version needed'])
    for sym_info in binary_info['symbol table']:
      # sym_info version field is an 1-based index on the version
      # information table
      # we don't care about 0 and 1 values:
      #  0 is for external symbol with no version information available
      #  1 is for a symbol defined by the binary and not binded
      #    to a version interface
      version_index = int(sym_info['version']) - 2
      if version_index >= 0:
        version = version_info[version_index]
        sym_info['version'] = version['version']
        if 'soname' in version:
          sym_info['soname'] = version['soname']
      else:
        sym_info['version'] = None

      # we make sure these fields are present
      # even if the syminfo section is not
      sym_info.setdefault('soname')
      sym_info.setdefault('flags')

  def _ParseElfdumpLine(self, line, section=None):

    headers_re = (
      r"""
       (?P<section>Version\sNeeded|Symbol\sTable  # Section header
                  |Version\sDefinition|Syminfo)
                   \sSection:
        \s+(?P<name>\.SUNW_version|\.gnu\.version_[rd]
            |\.(SUNW_l)?dynsym|\.SUNW_syminfo|.symtab)\s*$

       |\s*(?:index\s+)?version\s+dependency\s*$  # Version needed header

       |\s*(?:index\s+)?file\s+version\s*$        # Version definition header

       |\s*index\s*value\s+size\s+type\s+bind     # Symbol table header
        \s+oth\s+ver\s+shndx\s+name\s*$

       |\s*index\s+fla?gs\s+bound\sto\s+symbol\s*$ # Syminfo header

       |\s*$                                      # There is always a blank
                                                  # line before a new section
       """)

    re_by_section = {
      'version definition': (r"""
        \s*(?:\[\d+\]\s+)?                # index: might be not present if no
                                          #        version binding is enabled
        (?P<version>\S+)                  # version
        (?:\s+(?P<dependency>\S+))?       # dependency
        (?:\s+\[\s(?:BASE|WEAK)\s\])?\s*$
                              """),
      'version needed': (r"""
        \s*(?:\[(?P<index>\d+)\]\s+)?     # index: might be not present if no
                                          #        version binding is enabled
        (?:(?P<soname>\S+)\s+             # file: can be absent if the same as
         (?!\[\s(?:INFO|WEAK)\s\]))?      #       the previous line,
                                          #       we make sure there is no
                                          #       confusion with version
        (?P<version>\S+)                  # version
        (?:\s+\[\s(?:INFO|WEAK)\s\])?\s*$ #
                          """),
      'symbol table': (r"""
         \s*\[\d+\]                       # index
         \s+(?:0x[0-9a-f]+|REG_G\d+)      # value
         \s+(?:0x[0-9a-f]+)               # size
         \s+(?P<type>\S+)                 # type
         \s+(?P<bind>\S+)                 # bind
         \s+(?:\S+)                       # oth
         \s+(?P<version>\S+)              # ver
         \s+(?P<shndx>\S+)                # shndx
         (?:\s+(?P<symbol>\S+))?\s*$      # name
                        """),
      'syminfo': (r"""
         \s*(?:\[\d+\])                   # index
         \s+(?P<flags>[ABCDFILNPS]+)      # flags

         \s+(?:(?:\[\d+\]                 # bound to: contains either
         \s+(?P<soname>\S+)|<self>)\s+)?  #  - library index and library name
                                          #  -  <self> for non external symbols

         (?P<symbol>\S+)\s*               # symbol
                   """),
      'symtab': (r"""
         .*                               # We don't care about this section
                   """)}

    elfdump_data = None
    m = re.match(headers_re, line, re.VERBOSE)
    if m:
      if m.lastindex:
        if m.group('name') == ".symtab":
          section = 'symtab'
        else:
          section = m.group('section').lower()
    elif section:
      m = re.match(re_by_section[section], line, re.VERBOSE)
      if m and m.lastindex:
        elfdump_data = m.groupdict()

    if not m:
      raise errors.StdoutSyntaxError("Could not parse %r" % line)

    return elfdump_data, section


if __name__ == '__main__':
  parser = optparse.OptionParser()
  parser.add_option("-i", "--input", dest="input_file",
                    help="Input file")
  parser.add_option("--debug", dest="debug",
                    action="store_true", default=False)
  options, args = parser.parse_args()
  if not options.input_file:
    sys.stdout.write("Please provide input file name. See --help\n")
    sys.exit(1)
  logging.basicConfig(level=logging.DEBUG)
  extractor = ElfExtractor(options.input_file, debug=options.debug)
  md5_sum = extractor.CollectBinaryElfinfo()
  return_struct = {
      'md5_sum': md5_sum,
  }
  print(json.dumps(return_struct, indent=2))
