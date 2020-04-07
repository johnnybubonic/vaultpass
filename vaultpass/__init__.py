import logging
import tempfile
import os
import subprocess
##
from . import logger
_logger = logging.getLogger('VaultPass')
##
import hvac.exceptions
##
from . import args
from . import auth
from . import clipboard
from . import config
from . import constants
from . import gpg_handler
from . import mounts
from . import pass_import
from . import QR


class VaultPass(object):
    client = None
    auth = None
    uri = None
    mount = None

    def __init__(self, mount, cfg = '~/.config/vaultpass.xml'):
        self.mname = mount
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

    def _getHandler(self, mount = None, func = 'read', *args, **kwargs):
        if func not in ('read', 'write', 'list'):
            _logger.error('Invalid func')
            _logger.debug('Invalid func; must be one of: read, write, list, update')
            raise ValueError('Invalid func')
        if not mount:
            mount = self.mname
        mtype = self.mount.getMountType(mount)
        handler = None
        if mtype == 'cubbyhole':
            if func == 'read':
                handler = self.mount.cubbyhandler.read_secret
            elif func == 'write':
                handler = self.mount.cubbyhandler.write_secret
            elif func == 'list':
                handler = self.mount.cubbyhandler.list_secrets
        elif mtype == 'kv1':
            if func == 'read':
                handler = self.client.secrets.kv.v1.read_secret
            elif func == 'write':
                handler = self.client.secrets.kv.v1.create_or_update_secret
            elif func == 'list':
                handler = self.client.secrets.kv.v1.list_secrets
        elif mtype == 'kv2':
            if func == 'read':
                handler = self.client.secrets.kv.v2.read_secret_version
            elif func == 'write':
                handler = self.client.secrets.kv.v2.create_or_update_secret
            elif func == 'list':
                handler = self.client.secrets.kv.v2.list_secrets
        if not handler:
            _logger.error('Could not get handler')
            _logger.debug('Could not get handler for mount {0}'.format(mount))
            raise RuntimeError('Could not get handler')
        return(handler)

    def _getMount(self):
        mounts_xml = self.cfg.xml.find('.//mounts')
        self.mount = mounts.MountHandler(self.client, mounts_xml = mounts_xml)
        if self.mname:
            # Check that the mount exists
            self.mount.getMountType(self.mname)
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

    def _pathExists(self, path, mount = None, *args, **kwargs):
        if not mount:
            mount = self.mname
        exists = False
        if self.mount.getPath(path, mount):
            exists = True
        return(exists)

    def convert(self,
                mount,
                force = False,
                gpghome = constants.GPG_HOMEDIR,
                pass_dir = constants.PASS_DIR,
                *args, **kwargs):
        pass  # TODO

    def copySecret(self, oldpath, newpath, mount, newmount, force = False, remove_old = False, *args, **kwargs):
        mtype = self.mount.getMountType(mount)
        oldexists = self._pathExists(oldpath, mount = mount)
        if not oldexists:
            _logger.error('oldpath does not exist')
            _logger.debug('The oldpath {0} does not exist'.format(oldpath))
            raise ValueError('oldpath does not exist')
        data = self.getSecret(oldpath, mount)
        # TODO: left off here
        newexists = self._pathExists(newpath, mount = mount)

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

    def getSecret(self,
                  path,
                  mount,
                  kname = None,
                  clip = None,
                  qr = None,
                  seconds = constants.CLIP_TIMEOUT,
                  printme = False,
                  *args, **kwargs):
        mtype = self.mount.getMountType(mount)
        args = {'path': path,
                'mount_point': mount}
        handler = self._getHandler(mount, func = 'read')
        try:
            data = handler(**args)
            if mtype in ('cubbyhole', 'kv1'):
                data = data['data']
            elif mtype == 'kv2':
                data = data['data']['data']
            if kname:
                data = data.get(kname)
        except hvac.exceptions.InvalidPath as e:
            lpath = path.split('/')
            path = '/'.join(lpath[0:-1])
            args = {'path': path,
                    'kname': lpath[-1],
                    'mount': mount,
                    'clip': clip,
                    'qr': qr,
                    'seconds': seconds,
                    'printme': printme}
            data = self.getSecret(**args)
        if qr is not None:
            data, has_x = QR.genQr(data, image = True)
            if has_x:
                fpath = tempfile.mkstemp(prefix = '.vaultpass.qr.', suffix = '.svg', dir = '/dev/shm')[1]
                _logger.debug('Writing to {0} so it can be displayed'.format(fpath))
                with open(fpath, 'wb') as fh:
                    fh.write(data.read())
                if printme:
                    _logger.debug('Opening {0} in the default image viwer application'.format(fpath))
                    cmd = subprocess.run(['xdg-open', fpath], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
                    if cmd.returncode != 0:
                        _logger.error('xdg-open returned non-zero status code')
                        for x in ('stdin', 'stdout'):
                            o = getattr(cmd, x)
                            if not o:
                                continue
                            o = o.decode('utf-8').strip()
                            if o != '':
                                _logger.debug('{0}: {1}'.format(x.upper(), o))
                    os.remove(fpath)
            elif printme:
                print(data.read())
        data.seek(0, 0)
        # TODO: clip, etc.
        return(data)

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
