# A common library for web apps.

from lib.python import configuration

connected_to_db = False

def ConnectToDatabase():
  """Connect to the database only if necessary.

  One problem with this approach might be that if the connection is lost, the
  script will never try to reconnect (unless it's done by the ORM).
  """
  global connected_to_db
  if not connected_to_db:
    configuration.SetUpSqlobjectConnection()
    connected_to_db = True

def MakeDirP(p):
  try:
    os.makedirs(p)
  except OSError as e:
    if e.errno == errno.EEXIST and os.path.isdir(p):
      pass
    else: raise web.internalerror('cannot mkdir %s: %s' % (p, e))


def StatsFullPath(md5_sum):
  # archive_base = "/opt/csw/var/lib/checkpkg/data"
  archive_base = "/var/opt/csw/lib/checkpkg/data"
  if not os.path.exists(archive_base):
    raise web.internalerror('%s does not exist' % archive_base)
  p_subdir1 = os.path.join(archive_base, md5_sum[0])
  MakeDirP(p_subdir1)
  p_subdir2 = os.path.join(p_subdir1, md5_sum[:2])
  MakeDirP(p_subdir2)
  basename = "%s-stats.json" % md5_sum
  return os.path.join(p_subdir2, basename)


class ReadOnlySrv4Stats(object):

  def GET(self, md5_sum):
    web.header('Content-type', 'application/x-vnd.opencsw.pkg;type=pkg-stats')
    full_path = StatsFullPath(md5_sum)
    try:
      with open(full_path, 'r') as fd:
        data = fd.read()
    except IOError as e:
      if e.errno == errno.ENOENT:
        raise web.notfound('The file was not found on disk')
      else:
        raise web.internalerror(e)
    return data
