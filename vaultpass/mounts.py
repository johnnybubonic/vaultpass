import copy
import logging
import re
import shutil
import time
import warnings
##
import dpath.util  # https://pypi.org/project/dpath/
import hvac.exceptions
##
from . import constants


_logger = logging.getLogger()
_mount_re = re.compile(r'^(?P<mount>.*)/$')
_subpath_re = re.compile(r'^/?(?P<path>.*)/$')
_kv_re = re.compile(r'^kv(?:-v)?(?P<version>[0-9]+)$')


# TODO: for all write operations, modify handler call to first check if path exists and patch if it does?


class CubbyHandler(object):
    # There is no upstream support for directly reading cubby. So we do it ourselves.
    # TODO: custom class/handler? https://hvac.readthedocs.io/en/stable/advanced_usage.html#custom-requests-http-adapter
    def __init__(self, client):
        self.client = client

    def create_or_update_secret(self, *args, **kwargs):
        # Alias function
        return(self.write_secret(*args, **kwargs))

    def list_secrets(self, path, mount_point = 'cubbyhole', *args, **kwargs):
        path = path.lstrip('/')
        uri = 'v1/{0}/{1}'.format(mount_point, path)
        resp = self.client._adapter.list(url = uri)
        return(resp.json())

    def read_secret(self, path, mount_point = 'cubbyhole', *args, **kwargs):
        path = path.lstrip('/')
        uri = 'v1/{0}/{1}'.format(mount_point, path)
        resp = self.client._adapter.get(url = uri)
        return(resp.json())

    def remove_secret(self, path, mount_point = 'cubbyhole', *args, **kwargs):
        path = path.lstrip('/')
        uri = 'v1/{0}/{1}'.format(mount_point, path)
        resp = self.client._adapter.delete(url = uri)
        return(resp.json())

    def update_secret(self, secret, path, mount_point = 'cubbyhole', *args, **kwargs):
        existing = self.read_secret(path, mount_point)
        data = existing.get('data')
        if not data:
            resp = self.write_secret(path, secret, mount_point = mount_point)
        else:
            data.update(secret)
            self.remove_secret(path, mount_point)
            resp = self.write_secret(path, data, mount_point)
        return(resp)

    def write_secret(self, path, secret, mount_point = 'cubbyhole', *args, **kwargs):
        path = path.lstrip('/')
        args = {'path': 'v1/{0}'.format('/'.join((mount_point, path)))}
        for k, v in secret.items():
            if k in args.keys():
                _logger.error('Cannot use reserved secret name')
                _logger.debug('Cannot use secret name {0} as it is reserved'.format(k))
                raise ValueError('Cannot use reserved secret name')
            args[k] = v
        resp = self.client.write(**args)
        return(resp)


class MountHandler(object):
    internal_mounts = ('identity', 'sys')

    def __init__(self, client, mounts_xml = None):
        self.client = client
        self.cubbyhandler = CubbyHandler(self.client)
        self.xml = mounts_xml
        self.mounts = {}
        self.paths = {}
        self.flatpaths = set()
        self.getSysMounts()

    def createMount(self, mount_name, mount_type = 'kv2'):
        orig_mtype = mount_type
        if mount_type not in constants.SUPPORTED_ENGINES:
            _logger.error('Invalid mount type')
            _logger.debug(('The mount type {0} is invalid. '
                           'It must be one of: {1}').format(mount_type, ', '.join(constants.SUPPORTED_ENGINES)))
            raise ValueError('Invalid mount type')
        options = {}
        r = _kv_re.search(mount_type)
        if r:
            mount_type = 'kv'
            options['version'] = r.groupdict()['version']
        created = False
        try:
            self.client.sys.enable_secrets_engine(mount_type,
                                                  path = mount_name,
                                                  description = 'Created automatically by VaultPass',
                                                  options = options)
            created = True
        except hvac.exceptions.InvalidPath as e:
            _logger.error('Invalid path')
            _logger.debug('The mount path {0} (type {1}) is invalid: {2}'.format(mount_name, orig_mtype, e))
            raise ValueError('Invalid path')
        except hvac.exceptions.InvalidRequest as e:
            _logger.error('Invalid request; does mount already exist?')
            _logger.debug(('The creation of mount path {0} (type {1}) generated an invalid request: '
                           '{2}. Does it already exist?').format(mount_name, orig_mtype, e))
        # Due to how KV2 is created, we can hit a timing/race condition.
        if orig_mtype == 'kv2' and created:
            time.sleep(2)
        return(created)

    def getMountType(self, mount):
        if not self.mounts:
            self.getSysMounts()
        mtype = self.mounts.get(mount)
        if not mtype:
            _logger.error('Mount not found in defined mounts')
            _logger.debug('The mount {0} was not found in the defined mounts.'.format(mount))
            raise ValueError('Mount not found in defined mounts')
        return(mtype)

    def getPath(self, path, mount):
        relpath = path.lstrip('/')
        fullpath = '/'.join((mount, relpath))
        if not self.paths:
            self.getSecretsTree()
        obj = dpath.util.get(self.paths, fullpath, None)
        return(obj)

    def getSecretNames(self, path, mount, version = None):
        reader = None
        mtype = self.getMountType(mount)
        secrets_list = []
        keypath = ['data']
        args = {'path': path,
                'mount_point': mount}
        if mtype == 'cubbyhole':
            reader = self.cubbyhandler.read_secret
        elif mtype == 'kv1':
            reader = self.client.secrets.kv.v1.read_secret
        elif mtype == 'kv2':
            if not any(((version is None), isinstance(version, int))):
                _logger.error('version parameter must be an integer or None')
                _logger.debug('The version parameter ({0}) must be an integer or None'.format(version))
                raise ValueError('version parameter must be an integer or None')
            reader = self.client.secrets.kv.v2.read_secret_version
            args['version'] = version
            keypath = ['data', 'data']
        data = reader(**args)
        try:
            # secrets_list = list(data.get('data', {}).keys())
            secrets_list = list(dpath.util.get(data, keypath, {}).keys())
        except (KeyError, TypeError):
            secrets_list = []
        return(secrets_list)

    def getSecretsTree(self, path = '/', mounts = None, version = None):
        if not mounts:
            mounts = self.mounts
        if isinstance(mounts, dict):
            mounts = list(mounts.keys())
        if not isinstance(mounts, list):
            mounts = [mounts]
        for mount in mounts:
            mtype = self.getMountType(mount)
            handler = None
            args = {'path': path,
                    'mount_point': mount}
            relpath = path.replace('//', '/').lstrip('/')
            fullpath = '/'.join((mount, relpath)).replace('//', '/').lstrip('/')
            if mtype == 'cubbyhole':
                handler = self.cubbyhandler
            elif mtype == 'kv1':
                handler = self.client.secrets.kv.v1
            elif mtype == 'kv2':
                if not any(((version is None), isinstance(version, int))):
                    _logger.error('version parameter must be an integer or None')
                    _logger.debug('The version parameter ({0}) must be an integer or None'.format(version))
                    raise ValueError('version parameter must be an integer or None')
                handler = self.client.secrets.kv.v2
            self.flatpaths.add(mount)
            flatpath = path.rstrip('/')
            self.flatpaths.add('/'.join((mount, flatpath)))
            if mount not in self.paths.keys():
                self.paths[mount] = {}
            try:
                _logger.debug('Fetching path {0} on mount {1}...'.format(path, mount))
                paths = handler.list_secrets(**args)
            except hvac.exceptions.InvalidPath:
                # It's a secret name or doesn't exist.
                _logger.debug('Path {0} on mount {1} is a secret, not a subdir.'.format(path, mount))
                dpath.util.new(self.paths, fullpath, self.getSecretNames(path, mount, version = version))
                continue
            # if 'data' not in paths.keys() or 'keys' not in paths['data'].keys():
            try:
                paths_list = paths['data']['keys']
            except (KeyError, TypeError):
                _logger.warning('Mount has no secrets/subdirs')
                _logger.debug('The mount {0} has no secrets or subdirectories'.format(mount))
                warnings.warn('Mount has no secrets/subdirs')
                continue
            for p in paths_list:
                p_relpath = '/'.join((relpath, p)).replace('//', '/').lstrip('/')
                p_fullpath = '/'.join((fullpath, p)).replace('//', '/').lstrip('/')
                _logger.debug(('Recursing getSecretsTree. '
                               'path={0} '
                               'fullpath={1} '
                               'relpath={2} '
                               'p={3} '
                               'p_relpath={4} '
                               'p_fullpath={5}').format(path,
                                                        fullpath,
                                                        relpath,
                                                        p,
                                                        p_relpath,
                                                        p_fullpath))
                self.getSecretsTree(path = p_relpath, mounts = mount)
        return(None)

    def getSysMounts(self):
        try:
            for mount, mount_info in self.client.sys.list_mounted_secrets_engines()['data'].items():
                r = _mount_re.search(mount)
                if r:
                    mount = r.group('mount')
                if mount in self.internal_mounts:
                    continue
                # Get the mount type.
                mtype = mount_info['type']
                if mtype == 'kv':
                    mntopts = mount_info['options']
                    if mntopts and isinstance(mntopts, dict):
                        mver = mntopts.get('version')
                        if mver == '2':
                            mtype = 'kv2'
                        elif mver == '1':
                            mtype = 'kv1'
                self.mounts[mount] = mtype
                _logger.debug('Added mountpoint {0} to mounts list with type {1}'.format(mount, mtype))
        except hvac.exceptions.Forbidden:
            _logger.warning('Client does not have permission to read /sys/mounts.')
        # TODO: should I blindly merge in instead?
        if self.xml:
            for mount in self.xml.findall('.//mount'):
                mname = mount.text
                mtype = mount.attrib.get('type', 'kv2')
                if mname not in self.mounts.keys():
                    self.mounts[mname] = mtype
                    _logger.debug('Added mountpoint {0} to mounts list with type {1}'.format(mount, mtype))
        return(None)

    def printer(self, path = '/', mounts = None, output = None, indent = 4):
        # def treePrint(obj, s = 'Password Store\n', level = 0):
        #     prefix = '├──'
        #     leading_prefix = '│'
        #     last_prefix = '└──'
        #     pass
        #     return(s)
        if output:
            output = output.lower()
        if output and output not in constants.SUPPORTED_OUTPUT_FORMATS:
            _logger.error('Invalid output format')
            _logger.debug(('The output parameter ("{0}") must be one of: '
                           '{0}, or None').format(output, ', '.join(constants.SUPPORTED_OUTPUT_FORMATS)))
            raise ValueError('Invalid output format')
        if output in ('pretty', 'yaml', 'json'):
            if not any(((indent is None), isinstance(indent, int))):
                _logger.error('indent parameter must be an integer or None')
                _logger.debug('The indent parameter ({0}) must be an integer or None'.format(indent))
                raise ValueError('indent parameter must be an integer or None')
        if not self.paths:
            self.getSecretsTree()
        _paths = {}
        if not mounts:
            mounts = self.mounts.keys()
        for m in mounts:
            _paths[m] = self.getPath(path, m)
        if output == 'json':
            import json
            return(json.dumps(_paths, indent = indent))
        elif output == 'yaml':
            import yaml  # https://pypi.org/project/PyYAML/
            # import pyaml  # https://pypi.python.org/pypi/pyaml
            return(yaml.dump(_paths, indent = indent))
        elif output == 'pretty':
            import pprint
            if indent is None:
                indent = 1
            return(pprint.pformat(_paths, indent = indent, width = shutil.get_terminal_size((80, 20)).columns))
        # elif output == 'tree':
        #     import tree  # TODO? Wayyy later.
        elif not output:
            return(str(_paths))
        return(None)
