import logging
import os
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

    def getClient(self):
        pass  # Dummy/placeholder func.
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
        self.role = self.xml.find('role').text
        self.secret = self.xml.find('secret').text
        self.client = hvac.Client(url = self.uri)
        self.client.auth_approle(self.role, secret_id = self.secret)
        self.authCheck()
        return(None)


class LDAP(_AuthBase):
    name = 'LDAP'
    config_name = 'ldap'
    username = None
    password = None
    mount = None

    def __init__(self, uri, auth_xml, *args, **kwargs):
        super().__init__(uri, auth_xml, *args, **kwargs)
        self.getClient()

    def getClient(self):
        self.username = self.xml.find('username').text
        self.password = self.xml.find('password').text
        _mntpt = self.xml.find('mountPoint')
        if _mntpt is not None:
            self.mount = _mntpt.text
        else:
            self.mount = 'ldap'
        self.client = hvac.Client(url = self.uri)
        self.client.auth.ldap.login(username = self.username,
                                    password = self.password,
                                    mount_point = self.mount)
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
            raise RuntimeError('Env var not populated')
        return(var)

    def _getFile(self, fpath):
        fpath = os.path.abspath(os.path.expanduser(fpath))
        with open(fpath, 'r') as fh:
            contents = fh.read().strip()
        return(contents)

    def getClient(self):
        _token = self.xml.text
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
                    except Exception as e:
                        pass
                    try:
                        self._getFile('~/.vault-token')
                    except Exception as e:
                        _exhausted = True
                if not self.token:
                    _logger.debug(('Unable to automatically determine token from '
                                   'environment variable or filesystem defaults'))
                    _logger.error('Cannot determine token')
                    raise RuntimeError('Cannot determine token')
            else:
                if a.startswith('env:'):
                    e = a.split(':', 1)
                    self.token = self._getEnv(e)
                else:
                    self.token = self._getFile(a)
