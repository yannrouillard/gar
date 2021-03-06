#!/usr/bin/env python2.6

from StringIO import StringIO
import anydbm
import cjson
import getpass
import logging
import os
import pycurl
import re
import urllib2
import httplib

import retry_decorator

DEFAULT_URL = "http://buildfarm.opencsw.org"

class Error(Exception):
  """Generic error."""


class ArgumentError(Error):
  """Wrong arguments passed."""


class RestCommunicationError(Error):
  """An error during REST request processing."""


class RestClient(object):

  PKGDB_APP = "/pkgdb/rest"
  RELEASES_APP = "/releases"

  def __init__(self, rest_url=DEFAULT_URL, username=None, password=None,
      debug=False):
    self.rest_url = rest_url
    self.username = username
    self.password = password
    self.debug = debug

  def ValidateMd5(self, md5_sum):
    if not re.match(r'^[0-9a-f]{32}$', md5_sum):
      raise ArgumentError('Passed argument is not a valid md5 sum: %r' % md5_sum)

  def GetPkgByMd5(self, md5_sum):
    self.ValidateMd5(md5_sum)
    url = self.rest_url + self.PKGDB_APP + "/srv4/%s/" % md5_sum
    logging.debug("GetPkgByMd5(): GET %s", url)
    try:
      data = urllib2.urlopen(url).read()
      return cjson.decode(data)
    except urllib2.HTTPError, e:
      logging.warning("%s -- %s", url, e)
      if e.code == 404:
        # Code 404 is fine, it means that the package with given md5 does not
        # exist.
        return None
      else:
        # Other HTTP errors are should be thrown.
        raise

  def GetPkgstatsByMd5(self, md5_sum):
    self.ValidateMd5(md5_sum)
    url = self.rest_url + self.PKGDB_APP + "/srv4/%s/pkg-stats/" % md5_sum
    logging.debug("GetPkgstatsByMd5(): GET %s", url)
    try:
      data = urllib2.urlopen(url).read()
      return cjson.decode(data)
    except urllib2.HTTPError, e:
      logging.warning("%s -- %s", url, e)
      if e.code == 404:
        # Code 404 is fine, it means that the package with given md5 does not
        # exist.
        return None
      else:
        # Other HTTP errors are should be thrown.
        raise

  @retry_decorator.Retry(tries=4, exceptions=(RestCommunicationError, httplib.BadStatusLine))
  def GetCatalogData(self, md5_sum):
    self.ValidateMd5(md5_sum)
    url = self.rest_url + self.PKGDB_APP + "/srv4/%s/catalog-data/" % md5_sum
    try:
      data = urllib2.urlopen(url).read()
      return cjson.decode(data)
    except urllib2.HTTPError as e:
      logging.warning("Could not fetch catalog data for %r: %r", url, e)
      raise

  def GetMaintainerByMd5(self, md5_sum):
    self.ValidateMd5(md5_sum)
    pkg = self.GetPkgByMd5(md5_sum)
    if not pkg:
      pkg = {"maintainer_email": "Unknown"}
    return {
        "maintainer_email": pkg["maintainer_email"],
    }

  def GetCatalogList(self):
    url = self.rest_url + self.PKGDB_APP + "/catalogs/"
    data = urllib2.urlopen(url).read()
    return cjson.decode(data)

  def GetCatalog(self, catrel, arch, osrel):
    if not catrel:
      raise ArgumentError("Missing catalog release.")
    url = (
        self.rest_url
        + self.PKGDB_APP
        + "/catalogs/%s/%s/%s/?quick=true" % (catrel, arch, osrel))
    logging.debug("GetCatalog(): GET %s", url)
    try:
      data = urllib2.urlopen(url).read()
      return cjson.decode(data)
    except urllib2.HTTPError as e:
      logging.warning("%s -- %s", url, e)
      return None

  def Srv4ByCatalogAndCatalogname(self, catrel, arch, osrel, catalogname):
    """Returns a srv4 data structure or None if not found."""
    url = self.rest_url + self.PKGDB_APP + (
        "/catalogs/%s/%s/%s/catalognames/%s/"
        % (catrel, arch, osrel, catalogname))
    logging.debug("Srv4ByCatalogAndCatalogname(): GET %s", url)
    # The server is no longer returning 404 when the package is absent.  If
    # a HTTP error code is returned, we're letting the application fail.
    data = urllib2.urlopen(url).read()
    return cjson.decode(data)

  def Srv4ByCatalogAndPkgname(self, catrel, arch, osrel, pkgname):
    """Returns a srv4 data structure or None if not found."""
    url = self.rest_url + self.PKGDB_APP + (
        "/catalogs/%s/%s/%s/pkgnames/%s/"
        % (catrel, arch, osrel, pkgname))
    logging.debug("Srv4ByCatalogAndPkgname(): GET %s", url)
    # The server is no longer returning 404 when the package is absent.  If
    # a HTTP error code is returned, we're letting the application fail.
    data = urllib2.urlopen(url).read()
    return cjson.decode(data)

  def _SetAuth(self, c):
    """Set basic HTTP auth options on given Curl object."""
    if self.username:
      logging.debug("Using basic AUTH for user %s", self.username)
      c.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
      c.setopt(pycurl.USERPWD, "%s:%s" % (self.username, self.password))
    else:
      logging.debug("User and password not set, not using HTTP AUTH")
    return c

  def RemoveSvr4FromCatalog(self, catrel, arch, osrel, md5_sum):
    url = (
        "%s%s/catalogs/%s/%s/%s/%s/"
        % (self.rest_url,
           self.RELEASES_APP,
           catrel, arch, osrel,
           md5_sum))
    logging.debug("DELETE @ URL: %s %s", type(url), url)
    c = pycurl.Curl()
    d = StringIO()
    h = StringIO()
    c.setopt(pycurl.URL, str(url))
    c.setopt(pycurl.CUSTOMREQUEST, "DELETE")
    c.setopt(pycurl.WRITEFUNCTION, d.write)
    c.setopt(pycurl.HEADERFUNCTION, h.write)
    c.setopt(pycurl.HTTPHEADER, ["Expect:"]) # Fixes the HTTP 417 error
    c = self._SetAuth(c)
    if self.debug:
      c.setopt(c.VERBOSE, 1)
    c.perform()
    http_code = c.getinfo(pycurl.HTTP_CODE)
    logging.debug(
        "DELETE curl getinfo: %s %s %s",
        type(http_code),
        http_code,
        c.getinfo(pycurl.EFFECTIVE_URL))
    c.close()
    if not (http_code >= 200 and http_code <= 299):
      raise RestCommunicationError(
          "%s - HTTP code: %s, content: %s"
          % (url, http_code, d.getvalue()))

  @retry_decorator.Retry(tries=4, exceptions=RestCommunicationError)
  def _CurlPut(self, url, data):
    """Makes a PUT request, potentially uploading data.

    Some pieces of information left from a few debugging sessions:

    The UPLOAD option must not be set or upload will not work.
    c.setopt(pycurl.UPLOAD, 1)

    This would disable the chunked encoding, but the problem only appears
    when the UPLOAD option is set.
    c.setopt(pycurl.HTTPHEADER, ["Transfer-encoding:"])
    """
    for key, value in data:
      assert isinstance(value, basestring), (value, type(value))
    c = pycurl.Curl()
    d = StringIO()
    h = StringIO()
    c.setopt(pycurl.URL, str(url))
    c.setopt(pycurl.HTTPPOST, data)
    c.setopt(pycurl.CUSTOMREQUEST, "PUT")
    c.setopt(pycurl.WRITEFUNCTION, d.write)
    c.setopt(pycurl.HEADERFUNCTION, h.write)
    # The empty Expect: header fixes the HTTP 417 error on the buildfarm,
    # related to the use of squid as a proxy (squid only supports HTML/1.0).
    c.setopt(pycurl.HTTPHEADER, ["Expect:"])
    c = self._SetAuth(c)
    if self.debug:
      c.setopt(c.VERBOSE, 1)
    c.perform()
    http_code = c.getinfo(pycurl.HTTP_CODE)
    logging.debug(
        "curl getinfo: %s %s %s",
        type(http_code),
        http_code,
        c.getinfo(pycurl.EFFECTIVE_URL))
    c.close()
    if http_code >= 400 and http_code <= 599:
      if not self.debug:
        # In debug mode, all headers are printed to screen, and we aren't
        # interested in the response body.
        logging.fatal("Response: %s %s", http_code, d.getvalue())
      raise RestCommunicationError("%s - HTTP code: %s" % (url, http_code))
    else:
      logging.debug("Response: %s %s", http_code, d.getvalue())
    return http_code

  def AddSvr4ToCatalog(self, catrel, arch, osrel, md5_sum):
    self.ValidateMd5(md5_sum)
    url = (
        "%s%s/catalogs/%s/%s/%s/%s/"
        % (self.rest_url,
           self.RELEASES_APP,
           catrel,
           arch,
           osrel,
           md5_sum))
    logging.debug("URL: %s %s", type(url), url)
    return self._CurlPut(url, [])

  def SavePkgstats(self, pkgstats):
    md5_sum = pkgstats['basic_stats']['md5_sum']
    url = self.rest_url + self.RELEASES_APP + "/srv4/%s/pkg-stats/" % md5_sum
    logging.debug("SavePkgstats(): url=%r", url)
    return self._CurlPut(url, [('pkgstats', cjson.encode(pkgstats))])

  def GetCatalogForGeneration(self, catrel, arch, osrel):
    url = (self.rest_url + self.PKGDB_APP + "/catalogs/%s/%s/%s/for-generation/"
           % (catrel, arch, osrel))
    data = urllib2.urlopen(url).read()
    return cjson.decode(data)

  def GetBasenamesByCatalogAndDir(self, catrel, arch, osrel, basedir):
    url = (
        self.rest_url
        + self.PKGDB_APP
        + "/catalogs/%s/%s/%s/pkgnames-and-paths-by-basedir?basedir=%s"
           % (catrel, arch, osrel, urlencode(basedir)))
    data = urllib2.urlopen(url).read()
    return cjson.decode(data)

  def GetCatalogTimingInformation(self, catrel, arch, osrel):
    url = (
      self.rest_url
      + self.PKGDB_APP
      + "/catalogs/%s/%s/%s/timing/" % (catrel, arch, osrel))
    data = urllib2.urlopen(url).read()
    return cjson.decode(data)


class CachedPkgstats(object):
  """Class responsible for holding and caching package stats.

  Wraps RestClient and provides a caching layer.
  """

  def __init__(self, filename):
    self.filename = filename
    self.d = anydbm.open("%s.db" % self.filename, "c")
    self.rest_client = RestClient()
    self.deps = anydbm.open("%s-deps.db" % self.filename, "c")

  def __del__(self):
    self.d.close()

  def GetPkgstats(self, md5):
    pkgstats = None
    if str(md5) in self.d:
      serialized_data = self.d[md5]
      try:
        return cjson.decode(serialized_data)
      except (TypeError, cjson.DecodeError) as e:
        logging.fatal('A problem with %r: %r', md5, e)
        del self.d[md5]
    if not pkgstats:
      pkgstats = self.rest_client.GetPkgstatsByMd5(md5)
      self.d[md5] = cjson.encode(pkgstats)
    return pkgstats

  def GetDeps(self, md5):
    if str(md5) in self.deps:
      return cjson.decode(self.deps[md5])
    else:
      data = self.rest_client.GetCatalogData(md5)
      self.deps[md5] = cjson.encode(data)
      return data


def GetUsernameAndPassword():
  username = os.environ["LOGNAME"]
  password = None
  authfile = os.path.join('/etc/opt/csw/releases/auth', username)
  try:
    with open(authfile, 'r') as af:
      password = af.read().strip()
  except IOError, e:
    logging.warning("Error reading %s: %s", authfile, e)
    password = getpass.getpass("{0}'s pkg release password> ".format(username))
  return username, password
