import logging
import tempfile
import os
import subprocess
import time
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

    def __init__(self, initialize = False, cfg = '~/.config/vaultpass.xml'):
        self.initialize = initialize
        self.cfg = config.getConfig(cfg)
        self._getURI()
        self.getClient()
        if not self.initialize:
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

    def _getConfirm(self, msg = None):
        if not msg:
            msg = 'Are you sure (y/N)? '
        confirm = input(msg)
        confirm = confirm.lower().strip()
        if confirm.startswith('y'):
            return(True)
        return(False)

    def _getHandler(self, mount, func = 'read', *args, **kwargs):
        if func not in ('read', 'write', 'list', 'delete', 'destroy'):
            _logger.error('Invalid func')
            _logger.debug('Invalid func; must be one of: read, write, list, delete, destroy')
            raise ValueError('Invalid func')
        mtype = self.mount.getMountType(mount)
        handler = None
        handler_map = {'cubbyhole': {'read': self.mount.cubbyhandler.read_secret,
                                     'write': self.mount.cubbyhandler.write_secret,
                                     'list': self.mount.cubbyhandler.list_secrets,
                                     'delete': self.mount.cubbyhandler.remove_secret,
                                     'destroy': self.mount.cubbyhandler.remove_secret},
                       'kv1': {'read': self.client.secrets.kv.v1.read_secret,
                               'write': self.client.secrets.kv.v1.create_or_update_secret,
                               'list': self.client.secrets.kv.v1.list_secrets,
                               'delete': self.client.secrets.kv.v1.delete_secret,
                               'destroy': self.client.secrets.kv.v1.delete_secret},
                       'kv2': {'read': self.client.secrets.kv.v2.read_secret_version,
                               'write': self.client.secrets.kv.v2.create_or_update_secret,
                               'list': self.client.secrets.kv.v2.list_secrets,
                               'delete': self.client.secrets.kv.v2.delete_secret_versions,
                               'destroy': self.client.secrets.kv.v2.destroy_secret_versions}}
        handler = handler_map.get(mtype, {}).get(func, None)
        if not handler:
            _logger.error('Could not get handler')
            _logger.debug('Could not get handler for function {0} on mount {1} (type {2})'.format(func, mount, mtype))
            raise RuntimeError('Could not get handler')
        return(handler)

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

    def _pathExists(self, path, mount, is_secret = False, *args, **kwargs):
        kname = None
        if is_secret:
            lpath = path.split('/')
            path = '/'.join(lpath[0:-1])
            kname = lpath[-1]
        path_obj = self.mount.getPath(path, mount)
        if path_obj:
            if not is_secret:
                return(True)
            else:
                if kname in path_obj.keys():
                    return(True)
        return(False)

    def convert(self,
                mount,
                force = False,
                gpghome = constants.GPG_HOMEDIR,
                pass_dir = constants.PASS_DIR,
                *args, **kwargs):
        pass  # TODO

    def copySecret(self, oldpath, newpath, mount, newmount = None, force = False, remove_old = False, *args, **kwargs):
        mtype = self.mount.getMountType(mount)
        if not newmount:
            newmount = mount
        oldexists = self._pathExists(oldpath, mount = mount)
        if not oldexists:
            _logger.error('oldpath does not exist')
            _logger.debug('The oldpath {0} does not exist'.format(oldpath))
            raise ValueError('oldpath does not exist')
        data = self.getSecret(oldpath, mount)
        if not data:
            _logger.error('No secret found')
            _logger.debug('The secret at path {0} on mount {1} does not exist.'.format(oldpath, mount))
        # TODO: left off here
        newexists = self._pathExists(newpath, mount = newmount)
        if newexists and not force:
            _logger.debug('The newpath {0}:{1} exists; prompting for confirmation.'.format(newmount, newpath))
            confirm = self._getConfirm('The destination {0} exists. Overwrite (y/N)?'.format(newpath))
            if not confirm:
                _logger.debug('Confirmation denied; skipping copy of {0}:{1} to {2}:{3}.'.format(mount,
                                                                                                 oldpath,
                                                                                                 newmount,
                                                                                                 newpath))
                print('Not overwriting.')
                return(None)
            _logger.debug('Confirmed overwriting copy of {0}:{1} to {1}:{2}.'.format(mount, oldpath, newmount, newpath))
        if newexists:
            self.deleteSecret(newpath, newmount, force = True)
        self.createSecret(data, newpath, newmount)
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

    def deleteSecret(self, path, mount, force = False, recursive = False, destroy = False, *args, **kwargs):
        mtype = self.mount.getMountType(mount)
        args = {'path': path,
                'mount_point': mount}
        if destroy:
            op = 'destroy'
        else:
            op = 'delete'
        handler = self._getHandler(mount, func = op)
        is_path = self._pathExists(path, mount)
        is_secret = self._pathExists(path, mount, is_secret = True)
        if is_path and not recursive and not force:
            _logger.debug('Path {0} is a subdir and not a specific key; prompting for confirmation'.format(path))
            confirm = self._getConfirm('{0}:{1} is a path, not a secret. {2} recursively? (y/N) '.format(mount,
                                                                                                         path,
                                                                                                         op.title()))
            if not confirm:
                _logger.debug('Confirmation denied; skipping recursive {0} of {1}:{2}.'.format(op, mount, path))
                print('Not deleting.')
                return(None)
            _logger.debug('Confirmed {0} of {1}:{2}.'.format(op, mount, path))
        elif is_path and not force:
            confirm = self._getConfirm('Really {0} path {1}:{2} recursively? (y/N) '.format(op, mount, path))
            if not confirm:
                _logger.debug('Confirmation denied; skipping recursive {0} of {1}:{2}.'.format(op, mount, path))
                return(None)
            _logger.debug('Confirmed {0} of {1}:{2}.'.format(op, mount, path))
        elif is_secret:
            lpath = path.split('/')
            kname = lpath[-1]
            path = '/'.join(lpath[0:-1])
            self.removeSecretName(kname, path, mount, force = force, destroy = destroy)
        return(handler(**args))

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
        if not self.client.sys.is_initialized() and not self.initialize:
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
            # Add return here?
            data = self.getSecret(**args)
        if qr not in (False, None):
            qrdata, has_x = QR.genQr(data, image = True)
            if has_x:
                fpath = tempfile.mkstemp(prefix = '.vaultpass.qr.', suffix = '.svg', dir = '/dev/shm')[1]
                _logger.debug('Writing to {0} so it can be displayed'.format(fpath))
                with open(fpath, 'wb') as fh:
                    fh.write(qrdata.read())
                if printme:
                    _logger.debug('Opening {0} in the default image viwer application'.format(fpath))
                    # We intentionally want this to block, as most image viewers will  unload the image once the file
                    # is deleted and we can probably delete it faster than the user can save it elsewhere or
                    # scan it with their phone.
                    # TODO: we could use Popen() and do a countdown for "seconds" seconds, and then kill the viewer.
                    #       But that breaks compat with Pass' behaviour.
                    if printme:
                        print('Now displaying generated QR code. Please close the viewer when done saving/scanning to '
                              'securely clean up the generated file...')
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
                    if printme:
                        print('Done. Deleting generated file.')
                    os.remove(fpath)
            elif printme:
                print(qrdata.read())
            qrdata.seek(0, 0)
            del(qrdata)
        if clip not in (False, None):
            clipboard.pasteClipboard(data, seconds = seconds, clipboard = clipboard, printme = printme)
        return(data)

    def initVault(self, *args, **kwargs):
        if not self.client.sys.is_initialized():
            init_rslt = self.client.sys.initialize(secret_shares = 1, secret_threshold = 1)
            unseal = init_rslt['keys_base64'][0]
            token = init_rslt['root_token']
            self.cfg.updateAuth(unseal, token)
            self.client.sys.submit_unseal_key(unseal)
            self.client.token = token
            # JUST in case.
            time.sleep(1)
            for mname, mtype in self.mount.mounts.items():
                if mtype == 'cubbyhole':
                    # There isn't a way to "create" a cubbyhole.
                    continue
                self.mount.createMount(mname, mtype)
        self._checkSeal()
        self._getMount()
        return(None)

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

    def removeSecretName(self, kname, path, mount, force = False, destroy = False, *args, **kwargs):
        # NOTE: this should edit a secret such that it removes a key from the dict at path.
        pass  # TODO

    def searchSecrets(self, pattern, mount, *args, **kwargs):
        pass  # TODO

    def searchSecretNames(self, pattern, mount, *args, **kwargs):
        pass  # TODO
