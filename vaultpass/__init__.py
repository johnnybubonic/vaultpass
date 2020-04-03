import logging
import os
##
from . import logger
_logger = logging.getLogger('VaultPass')
from . import args
from . import auth
from . import clipboard
from . import config
from . import constants
from . import mounts
from . import pass_import


class PassMan(object):
    client = None
    auth = None
    uri = None
    mount = None

    def __init__(self, cfg = '~/.config/vaultpass.xml'):
        self.cfg = config.getConfig(cfg)
        self._getURI()
        self.getClient()
        self._checkSeal()
        self._getMount()

    def _checkSeal(self):
        _logger.debug('Checking and attempting unseal if necessary and possible.')
        if not self.client.sys.is_sealed():
            _logger.debug('Unsealing unnecessary; Vault is already unsealed.')
            return(None)
        shard = self.cfg.xml.find('unseal')
        if shard is None:
            _logger.debug('Vault is sealed but no key shard was provided.')
            _logger.error('Vault is sealed')
            raise RuntimeError('Vault is sealed')
        self.client.sys.submit_unseal_key(shard.text)
        if self.client.sys.is_sealed:
            _logger.debug(('Vault is sealed and either our unseal shard is incorrect or it is not enough to meet the '
                           'unseal shard threshold.'))
            _logger.error('Unable to unseal')
            raise RuntimeError('Unable to unseal')
        return(None)

    def _getMount(self):
        mounts_xml = self.cfg.xml.find('.//mounts')
        self.mount = mounts.MountHandler(self.client, mounts_xml = mounts_xml)
        return(None)

    def _getURI(self):
        uri = self.cfg.xml.find('.//uri')
        if uri is None:
            _logger.debug('No server URI specified; checking ${VAULT_ADDR}')
            _uri = os.environ.get('VAULT_ADDR')
            if not _uri:
                _logger.debug('No ${VAULT_ADDR}; using default of http://localhost:8200/')
                uri = 'http://localhost:8200/'
            else:
                uri = _uri
        else:
            uri = uri.text
        self.uri = uri
        _logger.debug('Set URI to {0}'.format(self.uri))
        return(None)

    def getClient(self):
        auth_xml = self.cfg.xml.find('.//auth')
        if auth_xml is None:
            _logger.debug('No auth section was found in the configuration file.')
            _logger.error('Could not find authentication')
            raise RuntimeError('Could not find authentication')
        authmethod_xml = auth_xml.getchildren()[0]
        _logger.debug('Attempting to auto-detect the authentication method...')
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
            _logger.debug('Found auth method: {0}'.format(self.auth.name))
            break
        if not self.auth:
            _logger.debug('Auth specified ({0}) was not found or is not supported'.format(authmethod_xml.tag))
            _logger.error('Invalid auth configuration')
            raise RuntimeError('Invalid auth configuration')
        self.client = self.auth.client
        if not self.client.sys.is_initialized():
            _logger.debug('Vault instance is not initialized. Please initialize (and configure, if necessary) first.')
            _logger.error('Not initialized')
            raise RuntimeError('Not initialized')
        return(None)
