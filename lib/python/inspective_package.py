"""This file isolates code dependent on elftools."""

import package
import os
import re
import sys
import logging
import sharedlib_utils
import magic
import copy
import common_constants
import ldd_emul
import configuration as c
import time
import shell
import mmap
import tempfile
import io

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_E_MACHINE

ROOT_RE = re.compile(r"^(reloc|root)/")


def StripRe(x, strip_re):
  return re.sub(strip_re, "", x)


def GetMachineIdOfBinary(full_path):
  with open(full_path, 'rb') as elf_fd:
    elffile = ELFFile(elf_fd)
    return ENUM_E_MACHINE[elffile.header['e_machine']]


def GetFileMetadata(file_magic, base_dir, file_path):
  full_path = unicode(os.path.join(base_dir, file_path))
  if not os.access(full_path, os.R_OK):
    return {}
  file_info = {
      "path": StripRe(file_path, ROOT_RE),
      "mime_type": file_magic.GetFileMimeType(full_path)
  }
  if base_dir:
    file_info["path"] = os.path.join(base_dir, file_info["path"])
  if not file_info["mime_type"]:
    logging.error("Could not establish the mime type of %s",
                  full_path)
    # We really don't want that, as it misses binaries.
    msg = (
        "It was not possible to establish the mime type of %s.  "
        "It's a known problem which occurs when indexing a large "
        "number of packages in a single run.  "
        "It's probably caused by a bug in libmagic, or a bug in "
        "libmagic Python bindings. "
        "Currently, there is no fix for it.  "
        "You have to restart your process - it "
        "will probably finish successfully when do you that."
        % full_path)
    if "/opt/csw/share" in full_path:
      file_info["mime_type"] = "application/octet-stream; fallback"
      logging.error(msg)
    else:
      raise package.PackageError(msg)
  if sharedlib_utils.IsBinary(file_info, check_consistency=False):
    file_info["machine_id"] = GetMachineIdOfBinary(full_path)
  return file_info

class InspectivePackage(package.DirectoryFormatPackage):
  """Extends DirectoryFormatPackage to allow package inspection."""

  def GetFilesMetadata(self):
    """Returns a data structure with all the files plus their metadata.

    [
      {
        "path": ...,
        "mime_type": ...,
      },
    ]
    """
    if not self.files_metadata:
      self.CheckPkgpathExists()
      self.files_metadata = []
      files_root = self.GetFilesDir()
      all_files = self.GetAllFilePaths()
      file_magic = FileMagic()
      basedir = self.GetBasedir()
      for file_path in all_files:
        full_path = unicode(self.MakeAbsolutePath(file_path))
        file_info = GetFileMetadata(file_magic, self.pkgpath, full_path)
        # To prevent files from containing the full temporary path.
        file_info["path"] = StripRe(file_path, ROOT_RE)
        self.files_metadata.append(file_info)
      file_magic.close()
    return self.files_metadata

  def ListBinaries(self):
    """Lists all the binaries from a given package.

    Original checkpkg code:

    #########################################
    # find all executables and dynamic libs,and list their filenames.
    listbinaries() {
      if [ ! -d $1 ] ; then
        print errmsg $1 not a directory
        rm -rf $EXTRACTDIR
        exit 1
      fi
      find $1 -print | xargs file |grep ELF |nawk -F: '{print $1}'
    }

    Returns a list of absolute paths.

    Now that there are files_metadata, this function can safely go away, once
    all its callers are modified to use files_metadata instead.
    """
    if self.binaries is None:
      self.CheckPkgpathExists()
      files_metadata = self.GetFilesMetadata()
      self.binaries = []
      # The nested for-loop looks inefficient.
      for file_info in files_metadata:
        if sharedlib_utils.IsBinary(file_info):
          self.binaries.append(file_info["path"])
      self.binaries.sort()
    return self.binaries

  def GetPathsInSubdir(self, remove_prefix, subdir):
    file_paths = []
    for root, dirs, files in os.walk(os.path.join(self.pkgpath, subdir)):
      full_paths = [os.path.join(root, f) for f in files]
      file_paths.extend([f.replace(remove_prefix, "") for f in full_paths])
    return file_paths

  def GetAllFilePaths(self):
    """Returns a list of all paths from the package."""
    if not self.file_paths:
      # Support for relocatable packages
      basedir = self.GetBasedir()
      self.CheckPkgpathExists()
      remove_prefix = "%s/" % self.pkgpath
      self.file_paths = self.GetPathsInSubdir(remove_prefix, "root")
      if self.RelocPresent():
        self.file_paths += self.GetPathsInSubdir(remove_prefix, "reloc")
    return self.file_paths

  def RelocPresent(self):
    return os.path.exists(os.path.join(self.directory, "reloc"))

  def GetFilesDir(self):
    """Returns the subdirectory in which files, are either "reloc" or "root"."""
    if self.RelocPresent():
      return "reloc"
    else:
      return "root"

  def GetBinaryDumpInfo(self):
    # Binaries. This could be split off to a separate function.
    # man ld.so.1 for more info on this hack
    env = copy.copy(os.environ)
    env["LD_NOAUXFLTR"] = "1"
    binaries_dump_info = []
    basedir = self.GetBasedir()
    for binary in self.ListBinaries():
      binary_abs_path = os.path.join(self.directory, self.GetFilesDir(), binary)
      if basedir:
        binary = os.path.join(basedir, binary)
      binary_base_name = os.path.basename(binary)

      args = [common_constants.DUMP_BIN, "-Lv", binary_abs_path]
      retcode, stdout, stderr = shell.ShellCommand(args, env)
      binary_data = ldd_emul.ParseDumpOutput(stdout)
      binary_data["path"] = binary
      binary_data["base_name"] = binary_base_name
      binaries_dump_info.append(binary_data)
    return binaries_dump_info

  def GetDefinedSymbols(self):
    """Returns text symbols (i.e. defined functions) for packaged ELF objects

    To do this we parse output lines from nm similar to the following. "T"s are
    the definitions which we are after.

      0000104000 D _lib_version
      0000986980 D _libiconv_version
      0000000000 U abort
      0000097616 T aliases_lookup
    """
    binaries = self.ListBinaries()
    defined_symbols = {}

    for binary in binaries:
      binary_abspath = os.path.join(self.directory, self.GetFilesDir(), binary)
      # Get parsable, ld.so.1 relevant SHT_DYNSYM symbol information
      args = ["/usr/ccs/bin/nm", "-p", "-D", binary_abspath]
      retcode, stdout, stderr = shell.ShellCommand(args, allow_error=True)
      if retcode:
        logging.error("%s returned an error: %s", args, stderr)
        # Should it just skip over an error?
        continue
      nm_out = stdout.splitlines()

      defined_symbols[binary] = []
      for line in nm_out:
        sym = self._ParseNmSymLine(line)
        if not sym:
          continue
        if sym['type'] not in ("T", "D", "B"):
          continue
        defined_symbols[binary].append(sym['name'])

    return defined_symbols

  def GetBinaryElfInfo(self):
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
    """
    binaries = self.ListBinaries()
    binaries_elf_info = {}
    base_dir = self.GetBasedir()

    for binary in binaries:
      binary_abspath = os.path.join(self.directory, self.GetFilesDir(), binary)
      if base_dir:
        binary = os.path.join(base_dir, binary)
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
            fd.write(elfdump_output_file.read())
          with open("/tmp/elfdump_stderr.log", "w") as fd:
            fd.write(stderr)
          msg = ("%s returned one or more errors: %s" % (args, stderr) +
                 "\n\n" +
                 "ERROR: elfdump invocation failed. Please copy this message " +
                 "and the above messages into your report and send " +
                 "as path of the error report. Logs are saved in " +
                 "/tmp/elfdump_std(out|err).log for your inspection.")
          raise package.Error(msg)

      symbols = {}
      binary_info = {'version definition': [],
                     'version needed': []}

      try:
        file_size = os.fstat(elfdump_output_file.fileno()).st_size
      except io.UnsupportedOperation:
        file_size = len(elfdump_output_file.getvalue())
      if not file_size:
        binary_info['symbol table'] = []
        binaries_elf_info[binary] = binary_info
        continue

      try:
        fileno = elfdump_output_file.fileno()
        elfdump_output = mmap.mmap(fileno, 0, prot=mmap.PROT_READ)
      except io.UnsupportedOperation:
        elfdump_output = elfdump_output_file

      cur_section = None
      for line in iter(elfdump_output.readline, ""):
        try:
          elf_info, cur_section = self._ParseElfdumpLine(line, cur_section)
        except package.StdoutSyntaxError as e:
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

      binaries_elf_info[binary] = binary_info

    return binaries_elf_info

  def _ParseNmSymLine(self, line):
    re_defined_symbol =  re.compile('[0-9]+ [ABDFNSTU] \S+')
    m = re_defined_symbol.match(line)
    if not m:
      return None
    fields = line.split()
    sym = { 'address': fields[0], 'type': fields[1], 'name': fields[2] }
    return sym

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
      raise package.StdoutSyntaxError("Could not parse %r" % line)

    return elfdump_data, section

  def GetDependencies(self):
    """Gets dependencies information.

    Returns:
      A tuple of (list, list) of depends and i_depends.
    """
    # The collection of dependencies needs to be a list (as opposed to
    # a set) because there might be duplicates and it's necessary to
    # carry that information.
    depends = []
    i_depends = []
    depend_file_path = os.path.join(self.directory, "install", "depend")
    if os.path.exists(depend_file_path):
      with open(depend_file_path, "r") as fd:
        for line in fd:
          fields = re.split(c.WS_RE, line)
          if len(fields) < 2:
            logging.warning("Bad depends line: %s", repr(line))
          if fields[0] == "P":
            pkgname = fields[1]
            pkg_desc = " ".join(fields[1:])
            depends.append((pkgname, pkg_desc))
          if fields[0] == "I":
            pkgname = fields[1]
            i_depends.append(pkgname)
    return depends, i_depends

  def GetObsoletedBy(self):
    """Collects obsolescence information from the package if it exists

    Documentation:
    http://wiki.opencsw.org/obsoleting-packages

    Returns:

    A dictionary of "has_obsolete_info", "syntax_ok" and
    "obsoleted_by" where obsoleted_by is a list of (pkgname,
    catalogname) tuples and has_obsolete_info and syntax_ok are
    booleans.

    If the package has not been obsoleted or the package predates the
    implementation of this mechanism, obsoleted_by is an empty list
    and has_obsolete_info will be False.

    If the package provides obsolescence information but the format of
    the information is invalid, syntax_ok will be False and the list
    may be empty.  It will always contain the valid entries.
    """

    has_obsolete_info = False
    obsoleted_syntax_ok = True
    obsoleted_by = []
    obsoleted_by_path = os.path.join(self.directory, "install", "obsolete")

    if os.path.exists(obsoleted_by_path):
      has_obsolete_info = True
      with open(obsoleted_by_path, "r") as fd:
        for line in fd:
          fields = re.split(c.WS_RE, line)
          if len(fields) < 2:
            obsoleted_syntax_ok = False
            logging.warning("Bad line in obsolete file: %s", repr(line))
            continue
          pkgname, catalogname = fields[0:2]
          obsoleted_by.append((pkgname, catalogname))

    return { "syntax_ok": obsoleted_syntax_ok,
             "obsoleted_by": obsoleted_by,
             "has_obsolete_info": has_obsolete_info }


class FileMagic(object):
  """Libmagic sometimes returns None, which I think is a bug.
  Trying to come up with a way to work around that.  It might not even be
  very helpful, but at least detects the issue and tries to work around it.
  """

  def __init__(self):
    self.cookie_count = 0
    self._magic_cookie = None

  def close(self):
    if self._magic_cookie is not None:
      self._magic_cookie.close()
      self._magic_cookie = None

  @property
  def magic_cookie(self):
    if not self._magic_cookie:
      self._magic_cookie = magic.open(self.cookie_count)
      self.cookie_count += 1
      self._magic_cookie.load()
      if "MAGIC_MIME" in dir(magic):
        flag = magic.MAGIC_MIME
      elif "MIME" in dir(magic):
        flag = magic.MIME
      self._magic_cookie.setflags(flag)
    return self._magic_cookie

  def GetFileMimeType(self, full_path):
    logging.debug("GetFileMimeType(%r)", full_path)
    mime = self.magic_cookie.file(full_path)
    if not mime:
      raise package.SystemUtilityError(
          "libmagic has failed to return the mime type of %r." % (full_path))
    return mime


class InspectiveCswSrv4File(package.CswSrv4File):
  """Allows to get the inspective version of the dir format pkg."""

  # The presence of this method makes it explicit that we want an inspective
  # version of the directory format package.
  def GetInspectivePkg(self):
    return self.GetDirFormatPkg()

  def GetDirFormatClass(self):
    return InspectivePackage
