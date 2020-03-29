import logging
##
from . import auth
from . import clipboard
from . import config
from . import logger


_logger = logging.getLogger('VaultPass')


class PassMan(object):
    client = None
    auth = None
    uri = None

    def __init__(self, cfg = '~/.config/vaultpass.xml'):
        self.cfg = config.getConfig(cfg)
        self._getURI()
        self.getClient()

    def _getURI(self):
        uri = self.cfg.xml.find('uri')
        if uri is None:
            uri = 'http://localhost:8000/'
        pass

    def getClient(self):
        # This may need to be re-tooled in the future.
        auth_xml = self.cfg.xml.find('auth')
        if auth_xml is None:
            raise RuntimeError('Could not find authentication')
        authmethod_xml = auth_xml.getchildren()[0]
        for a in dir(auth):
            if a.startswith('_'):
                continue
            c = getattr(auth, a)
            if not c:
                continue
            confname = getattr(c, 'config_name')
            if not confname or confname != authmethod_xml.tag:
                continue
            self.auth = c(self.uri,
                          authmethod_xml)
            break
        if not self.auth:
            _logger.error('Invalid auth configuration')
            _logger.debug('Auth specified ({0}) was not found or is not supported'.format(authmethod_xml.tag))
            raise RuntimeError('Invalid auth configuration')
        self.client = self.auth.client
        return(None)
