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
from . import gpg_handler
from . import mounts
from . import pass_import


class VaultPass(object):
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

    def convert(self,
                mount,
                force = False,
                gpghome = constants.GPG_HOMEDIR,
                pass_dir = constants.PASS_DIR,
                *args, **kwargs):
        pass  # TODO

    def copySecret(self, oldpath, newpath, mount, newmount, force = False, remove_old = False, *args, **kwargs):
        pass  # TODO

        if remove_old:
            self.deleteSecret(oldpath, mount, force = force)
        return(None)

    def createSecret(self, secret_dict, path, mount_name, *args, **kwargs):
        mtype = self.mount.mounts.get(mount_name)
        handler = None
        if not mtype:
            _logger.error('Could not determine mount type')
            _logger.debug('Could not determine mount type for mount {0}'.format(mount_name))
            raise RuntimeError('Could not determine mount type')
        args = {'path': path,
                'mount_point': mount_name,
                'secret': secret_dict}
        if mtype == 'cubbyhole':
            handler = self.mount.cubbyhandler.write_secret
        elif mtype == 'kv1':
            handler = self.client.secrets.kv.v1.create_or_update_secret
        elif mtype == 'kv2':
            handler = self.client.secrets.kv.v2.create_or_update_secret
        resp = handler(**args)
        return(resp)

    def deleteSecret(self, path, mount_name, force = False, recursive = False, *args, **kwargs):
        pass  # TODO

    def editSecret(self, path, mount, editor = constants.EDITOR, *args, **kwargs):
        pass  # TODO

    def generateSecret(self,
                       path,
                       mount,
                       symbols = True,
                       clip = False,
                       seconds = constants.CLIP_TIMEOUT,
                       chars = constants.SELECTED_PASS_CHARS,
                       chars_plain = constants.SELECTED_PASS_NOSYMBOL_CHARS,
                       in_place = False,
                       qr = False,
                       force = False,
                       length = constants.GENERATED_LENGTH,
                       *args, **kwargs):
        pass  # TODO

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

    def getSecret(self, path, mount, clip = None, qr = None, seconds = constants.CLIP_TIMEOUT, *args, **kwargs):
        pass  # TODO

    def initVault(self, *args, **kwargs):
        pass  # TODO

    def insertSecret(self,
                     path,
                     mount,
                     allow_shouldersurf = False,
                     multiline = False,
                     force = False,
                     confirm = True,
                     *args, **kwargs):
        pass  # TODO

    def listSecretNames(self, path, mount, output = None, indent = 4, *args, **kwargs):
        pass  # TODO

    def searchSecrets(self, pattern, mount, *args, **kwargs):
        pass  # TODO

    def searchSecretNames(self, pattern, mount, *args, **kwargs):
        pass  # TODO
