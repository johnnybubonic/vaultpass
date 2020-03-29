import io
import logging
import os
##
import gpg  # https://pypi.org/project/gpg/


_logger = logging.getLogger()


class GPG(object):
    home = None
    gpg = None

    def __init__(self, home = None):
        if home:
            self.home = home
        self.initHome()

    def decrypt(self, fpath):
        fpath = os.path.abspath(os.path.expanduser(fpath))
        with open(fpath, 'rb') as fh:
            iobuf = io.BytesIO(fh.read())
        iobuf.seek(0, 0)
        rslt = self.gpg.decrypt(iobuf)
        decrypted = rslt[0]
        return(decrypted)

    def initHome(self):
        if not self.home:
            h = os.environ.get('GNUPGHOME')
            if h:
                self.home = h
        if self.home:
            self.home = os.path.abspath(os.path.expanduser(self.home))
            if not os.path.isdir(self.home):
                raise ValueError('GPG home does not exist')
            _logger.debug('Set GPG home to explicitly specified value {0}'.format(self.home))
        return(None)