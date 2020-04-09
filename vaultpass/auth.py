import logging
import os
import warnings
##
import hvac


_logger = logging.getLogger()


class _AuthBase(object):
    name = '_AuthBase'
    client = None

    def __init__(self, uri, auth_xml, *args, **kwargs):
        self.uri = uri
        self.xml = auth_xml
        _logger.debug('Intialized instance of {0}'.format(self.name))

    def authCheck(self):
        if not self.client.is_authenticated():
            _logger.debug('Could not authenticate to {0} using {1}.'.format(self.uri, self.name))
            _logger.error('Could not authenticate')
            raise RuntimeError('Could not authenticate')
        return(None)

    def getClient(self):
        pass  # Dummy/placeholder func.
        return(None)


class _BasicAuthBase(_AuthBase):
    name = '_BasicAuthBase'
    client = None
    username = None
    password = None
    mount = None

    def __init__(self, uri, auth_xml, default_mountpoint = 'userpass', *args, **kwargs):
        super().__init__(uri, auth_xml, *args, **kwargs)
        self.default_mountpoint = default_mountpoint
        self.setCreds()

    def setCreds(self):
        self.username = self.xml.find('.//username').text
        _logger.debug('Set username: {0}'.format(self.username))
        self.password = self.xml.find('.//password').text
        _logger.debug('Set password: {0}'.format(self.password))
        _mntpt = self.xml.find('.//mountPoint')
        if _mntpt is not None:
            self.mount = _mntpt.text
        else:
            self.mount = self.default_mountpoint
        _logger.debug('Set mountpoint: {0}'.format(self.mount))
        self.client = hvac.Client(url = self.uri)
        _logger.info('Initialized client.')
        return(None)


class AppRole(_AuthBase):
    name = 'AppRole'
    config_name = 'appRole'
    role = None
    secret = None

    def __init__(self, uri, auth_xml, *args, **kwargs):
        super().__init__(uri, auth_xml, *args, **kwargs)
        self.getClient()

    def getClient(self):
        self.role = self.xml.find('.//role').text
        _logger.debug('Set role: {0}'.format(self.role))
        self.secret = self.xml.find('.//secret').text
        _logger.debug('Set secret: {0}'.format(self.secret))
        self.client = hvac.Client(url = self.uri)
        _logger.info('Initialized client.')
        self.client.auth_approle(self.role, secret_id = self.secret)
        _logger.debug('Attempted to authenticate client.')
        self.authCheck()
        return(None)


class LDAP(_BasicAuthBase):
    name = 'LDAP'
    config_name = 'ldap'

    def __init__(self, uri, auth_xml, *args, **kwargs):
        super().__init__(uri, auth_xml, default_mountpoint = 'ldap', *args, **kwargs)
        self.getClient()

    def getClient(self):
        self.client.auth.ldap.login(username = self.username,
                                    password = self.password,
                                    mount_point = self.mount)
        _logger.debug('Attempted to authenticate client.')
        self.authCheck()
        return(None)


class Token(_AuthBase):
    name = 'Token'
    config_name = 'token'
    token = None

    def __init__(self, uri, auth_xml, *args, **kwargs):
        super().__init__(uri, auth_xml, *args, **kwargs)
        self.getClient()

    def _getEnv(self, env_var):
        var = os.environ.get(env_var)
        if not var:
            _logger.debug(('Environment variable {0} was specified as containing the token '
                           'but it is empty').format(env_var))
            _logger.error('Env var not populated')
            raise OSError('Env var not populated')
        return(var)

    def _getFile(self, fpath):
        fpath = os.path.abspath(os.path.expanduser(fpath))
        with open(fpath, 'r') as fh:
            contents = fh.read().strip()
        return(contents)

    def getClient(self):
        _token = self.xml.text
        chk = True
        if _token is not None:
            self.token = _token
        else:
            # First we check the attrib.
            a = self.xml.attrib.get('source')
            if not a:
                _exhausted = False
                # try, in order, env var and then ~/.vault-token
                while not _exhausted:
                    try:
                        self._getEnv('VAULT_TOKEN')
                        break
                    except OSError as e:
                        pass
                    try:
                        self._getFile('~/.vault-token')
                        _exhausted = True
                    except Exception as e:
                        _exhausted = True
                if not self.token:
                    _logger.debug(('Unable to automatically determine token from '
                                   'environment variable or filesystem defaults. Ignore this if you are initializing '
                                   'Vault.'))
                    _logger.warning('Cannot determine token')
                    warnings.warn('Cannot determine token')
                    chk = False
            else:
                if a.startswith('env:'):
                    e = a.split(':', 1)
                    self.token = self._getEnv(e)
                else:
                    self.token = self._getFile(a)
        _logger.debug('Set token: {0}'.format(self.token))
        self.client = hvac.Client(url = self.uri)
        _logger.info('Initialized client.')
        self.client.token = self.token
        _logger.debug('Applied token.')
        if chk:
            self.authCheck()
        return(None)


class UserPass(_BasicAuthBase):
    name = 'UserPass'
    config_name = 'userpass'

    def __init__(self, uri, auth_xml, *args, **kwargs):
        super().__init__(uri, auth_xml, default_mountpoint = 'userpass', *args, **kwargs)
        self.getClient()

    def getClient(self):
        resp = self.client.auth.userpass.login(username = self.username,
                                               password = self.password,
                                               mount_point = self.mount)
        _logger.debug('Attempted to authenticate client.')
        try:
            self.client.token = resp['auth']['client_token']
        except KeyError:
            # Auth failed. We'll let authCheck() handle the error.
            pass
        self.authCheck()
        return(None)
