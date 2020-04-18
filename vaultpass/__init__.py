import getpass
import logging
import tempfile
import os
import pathlib
import re
import subprocess
import sys
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
from . import editor
from . import gpg_handler
from . import mounts
from . import pwgen
from . import QR


class VaultPass(object):
    client = None
    auth = None
    uri = None
    mount = None

    def __init__(self,
                 initialize = False,
                 cfg = '~/.config/vaultpass.xml',
                 verify_cfg = True,
                 loglevel = constants.DEFAULT_LOGLEVEL,
                 *args,
                 **kwargs):
        rootlogger = logging.getLogger()
        if loglevel != constants.DEFAULT_LOGLEVEL:
            if not isinstance(loglevel, int):
                # We need to convert it from the name to the int.
                loglevel = getattr(logging, loglevel.upper())
        if loglevel != constants.DEFAULT_LOGLEVEL:  # And again in case we transformed it above.
            rootlogger.setLevel(loglevel)
        self.initialize = initialize
        self.cfg = config.getConfig(cfg, validate = verify_cfg)
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
        funcs = ('read', 'write', 'list', 'delete', 'destroy')
        if func not in funcs:
            _logger.error('Invalid func')
            _logger.debug('Invalid func; must be one of: {0}'.format(', '.join(funcs)))
            raise ValueError('Invalid func')
        mtype = self.mount.getMountType(mount)
        handler = None
        handler_map = {'cubbyhole': {'read': self.mount.cubbyhandler.read_secret,
                                     'write': self.mount.cubbyhandler.write_secret,
                                     'list': self.mount.cubbyhandler.list_secrets,
                                     'delete': self.mount.cubbyhandler.remove_secret,
                                     'destroy': self.mount.cubbyhandler.remove_secret,
                                     'update': self.mount.cubbyhandler.update_secret},
                       'kv1': {'read': self.client.secrets.kv.v1.read_secret,
                               'write': self.client.secrets.kv.v1.create_or_update_secret,
                               'list': self.client.secrets.kv.v1.list_secrets,
                               'delete': self.client.secrets.kv.v1.delete_secret,
                               'destroy': self.client.secrets.kv.v1.delete_secret,
                               'update': self.client.secrets.kv.v1.create_or_update_secret},
                       'kv2': {'read': self.client.secrets.kv.v2.read_secret_version,
                               'write': self.client.secrets.kv.v2.create_or_update_secret,
                               'list': self.client.secrets.kv.v2.list_secrets,
                               'delete': self.client.secrets.kv.v2.delete_latest_version_of_secret,
                               'destroy': self.client.secrets.kv.v2.delete_metadata_and_all_versions,
                               'update': self.client.secrets.kv.v2.create_or_update_secret}}
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
                flat = False,
                *args, **kwargs):
        pass_dir = os.path.abspath(os.path.expanduser(pass_dir))
        gpg = gpg_handler.GPG(home = gpghome)
        kname_re = re.compile(r'^(?P<kname>[^/]+)\.(gpg|asc)$')
        for root, dirs, files in os.walk(pass_dir):
            rel_root = pathlib.Path(root).relative_to(pass_dir)
            for f in files:
                r = kname_re.search(f)
                if not r:
                    continue
                kname = r.groupdict()['kname']
                dcryptdata = gpg.decrypt(os.path.join(root, f)).decode('utf-8')
                if flat:
                    path = os.path.dirname(rel_root)
                    data = {kname: dcryptdata}
                    self.createSecret(data, path, mount, force = force)
                else:
                    data = {}
                    k = None
                    v = ''
                    for line in dcryptdata.splitlines():
                        l = [i.strip() for i in line.split(':', 1) if i.strip() != '']
                        if len(l) == 1:
                            v += '\n{0}'.format(l[0])
                        elif len(l) == 0:
                            continue
                        else:
                            data[k] = v
                            k = l[0]
                            v = l[1]
                    self.createSecret(data, path = '/'.join((rel_root, kname)), mount = mount, force = force)
        return(None)

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

    def createSecret(self, secret_dict, path, mount, force = False, *args, **kwargs):
        mtype = self.mount.mounts.get(mount)
        if not mtype:
            _logger.error('Could not determine mount type')
            _logger.debug('Could not determine mount type for mount {0}'.format(mount))
            raise RuntimeError('Could not determine mount type')
        args = {'path': path,
                'mount_point': mount,
                'secret': secret_dict}
        path_exists = self._pathExists(path, mount)
        if path_exists:
            for k in secret_dict.keys():
                kpath = '/'.join(path, k)
                exists = self._pathExists(kpath, mount, is_secret = True)
                if exists:
                    _logger.warning('A secret named {0} at {1}:{2} exists.'.format(k, mount, path))
                    if not force:
                        _logger.error('Cannot create secret; a name already exists.')
                        raise ValueError('Cannot create secret; a name already exists.')
        if path_exists:
            handler = self._getHandler(mount, func = 'update')
        else:
            handler = self._getHandler(mount, func = 'write')
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
            self.removeSecretName(kname, path, mount, destroy = destroy)
        # The business end.
        if op == 'destroy':
            if mtype == 'kv2':
                versions = self.client.secrets.kv.v2.
        return(handler(**args))

    def editSecret(self, path, mount, editor_prog = constants.EDITOR, *args, **kwargs):
        data = self.getSecret(path, mount)
        newdata, fpath = editor.Editor(data, editor = editor_prog)
        print('Done. Deleting generated file.')
        os.remove(fpath)
        self.createSecret(newdata, path, mount, force = True)
        return(newdata)

    def generateSecret(self,
                       path,
                       mount,
                       kname = None,
                       symbols = True,
                       clip = False,
                       seconds = constants.CLIP_TIMEOUT,
                       chars = constants.SELECTED_PASS_CHARS,
                       chars_plain = constants.SELECTED_PASS_NOSYMBOL_CHARS,
                       in_place = False,
                       qr = False,
                       force = False,
                       length = constants.GENERATED_LENGTH,
                       printme = False,
                       *args, **kwargs):
        charset = {'simple': chars_plain,
                   'complex': chars}
        pg_args = {'length': length,
                   'chars': charset,
                   'charset': ('complex' if symbols else 'simple')}
        pg = pwgen.genPass(**pg_args)
        pg.genPW()
        passwd = pg.pw
        if not kname:
            lpath = path.split('/')
            kname = lpath[-1]
            path = '/'.join(lpath[0:-1])
        args = {'secret_dict': {kname: passwd},
                'path': path,
                'mount': mount,
                'force': force}
        self.createSecret(**args)
        self.getSecret(path, mount, kname = kname, clip = clip, qr = qr, seconds = seconds, printme = printme)
        return(passwd)

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
                              'securely clean up the generated file and continue...')
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
            clipboard.pasteClipboard(data, seconds = seconds, printme = printme)
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
        # This is a function that's mostly sugar for the CLI part.
        # If you're using VaultPass as a python library, you'll probably just want to skip directly to
        # self.createSecret().
        orig_path = path
        lpath = path.split('/')
        kname = lpath[-1]
        path = '/'.join(lpath[0:-1])
        is_tty = sys.stdin.isatty()
        if not is_tty:  # It's a pipe (or cron or something, but that'd be dumb for this).
            secret = ''
            end = ['']
            if not multiline:
                end.append('\n')
            while True:
                c = sys.stdin.read(1)
                if c in end:
                    break
                secret += c
        else:  # It's an interactive shell.
            if allow_shouldersurf:
                msg = 'Secret/password:'
            else:
                msg = 'Secret/password (will NOT echo back):'
            if multiline:
                print('{0} (ctrl-D when done)\n'.format(msg))
                if allow_shouldersurf:
                    secret = sys.stdin.readlines()
                else:
                    # This gets a *little* hacky.
                    # Inspiration from https://stackoverflow.com/a/10426831/733214
                    secret = []
                    try:
                        while True:
                            try:
                                i = getpass.getpass('')
                                secret.append(i)
                            except EOFError:
                                break
                    except KeyboardInterrupt:
                        pass
                secret = '\n'.join(secret)
        if confirm:
            _logger.debug('Getting confirmation to write to {0} ({1}) on mount {2}'.format(path, kname, mount))
            confirmation = self._getConfirm('Write to {0}:{1} ({2})? (y/N) '.format(mount, path, kname))
            if not confirmation:
                _logger.debug('Confirmation denied; skipping.')
                return(None)
        exists = self._pathExists(orig_path, mount, is_secret = True)
        data = {}
        if exists:
            if not force:
                _logger.debug('Getting confirmation to update/replace {0} ({1}) on mount {2}'.format(path,
                                                                                                     kname,
                                                                                                     mount))
                confirmation = self._getConfirm(('Secret name {0} at path {1} on mount {2} exists. '
                                                 'Overwrite/update? (y/N) ').format(kname, path, mount))
                if not confirmation:
                    _logger.debug('Confirmation denied; skipping.')
                    return(None)
            data = self.getSecret(path, mount, kname = kname)
        data[kname] = secret
        self.createSecret(data, path, mount, force = force)
        return(None)

    def listSecretNames(self, path, mount, output = None, indent = 4, *args, **kwargs):
        exists = self._pathExists(path, mount)
        is_secret = self._pathExists(path, mount, is_secret = True)
        if not any((exists, is_secret)):
            _logger.error('Invalid path')
            _logger.debug('Path {0} on mount {1} is invalid/does not exist.'.format(path, mount))
            raise ValueError('Invalid path')
        self.mount.getSecretsTree(path = path, mounts = mount)
        outstr = self.mount.printer(path = path, mounts = mount, output = output, indent = indent)
        print(outstr)
        return(None)

    def removeSecretName(self, kname, path, mount, destroy = False, *args, **kwargs):
        # NOTE: this should edit a secret such that it removes a key from the dict at path.
        data = self.getSecret(path, mount)
        if kname not in data:
            _logger.error('Secret name does not exist')
            _logger.debug('Secret name {0} does not exist in {1}:{2}.'.format(kname, mount, path))
            raise ValueError('Secret name does not exist')
        del(data[kname])
        # TODO: handle destroy?
        self.createSecret(data, path, mount, force = True)
        return(data)

    def searchSecrets(self, pattern, mount, *args, **kwargs):
        print('This may take a while...')
        ptrn = re.compile(pattern)
        self.mount.getSecretsTree(mounts = mount)
        for p in self.mount.flatpaths:
            data = self.getSecret(p, mount)
            if data:
                for k, v in data.items():
                    if ptrn.search(v):
                        print('/'.join((mount, p, k)))
        return(None)

    def searchSecretNames(self, pattern, mount, *args, **kwargs):
        ptrn = re.compile(pattern)
        self.mount.getSecretsTree(mounts = mount)
        for p in self.mount.flatpaths:
            n = p.split('/')[-1]
            if ptrn.search(n):
                print(p)
        return(None)
