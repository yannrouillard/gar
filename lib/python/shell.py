import logging
import os
import signal
import subprocess

from lib.python import errors

class ShellError(errors.Error):
  """Problem running a shell command."""


class TimeoutExpired(errors.Error):
  """Command running for too long."""


def TimeoutHandler(signum, frame):
  raise TimeoutExpired

def ShellCommand(args, env=None,
                 timeout=None,
                 quiet=True,
                 allow_error=False,
                 stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE):
  logging.debug("ShellCommand(%r)", args)
  if not env:
    env = {}

  env['LC_ALL'] = 'C'

  # Python 3.3 have the timeout option
  # we have to roughly emulate it with python 2.x
  if timeout:
    signal.signal(signal.SIGALRM, TimeoutHandler)
    signal.alarm(timeout)

  try:
    proc = subprocess.Popen(args,
                            stdout=stdout,
                            stderr=stderr,
                            env=env,
                            preexec_fn=os.setsid,
                            close_fds=True)
    stdout, stderr = proc.communicate()
    retcode = proc.wait()
    signal.alarm(0)
  except TimeoutExpired:
    os.kill(-proc.pid, signal.SIGKILL)
    msg = "Process %s killed after timeout expiration" % args
    raise TimeoutExpired(msg)

  if retcode and not allow_error:
    logging.critical(stdout)
    logging.critical(stderr)
    raise ShellError("Running %r has failed, error code: %s" % (args, retcode))

  return retcode, stdout, stderr

def MakeDirP(self, dir_path):
  """mkdir -p equivalent.

  http://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
  """
  try:
    os.makedirs(dir_path)
  except OSError as e:
    if e.errno == errno.EEXIST:
      pass
    else:
      raise
