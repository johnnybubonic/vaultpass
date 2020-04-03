import logging
import re
import shutil
import warnings
##
import dpath.util  # https://pypi.org/project/dpath/
import hvac.exceptions


_logger = logging.getLogger()
_mount_re = re.compile(r'^(?P<mount>.*)/$')
_subpath_re = re.compile(r'^/?(?P<path>.*)/$')


class CubbyHandler(object):
    # There is no upstream support for directly reading cubby. So we do it ourselves.
    # TODO: custom class/handler? https://hvac.readthedocs.io/en/stable/advanced_usage.html#custom-requests-http-adapter
    def __init__(self, client):
        self.client = client

    def list_secrets(self, path, mount_point = 'cubbyhole'):
        path = path.lstrip('/')
        uri = '/v1/{0}/{1}'.format(mount_point, path)
        resp = self.client._adapter.list(url = uri)
        return(resp.json())

    def read_secret(self, path, mount_point = 'cubbyhole'):
        path = path.lstrip('/')
        uri = '/v1/{0}/{1}'.format(mount_point, path)
        resp = self.client._adapter.get(url = uri)
        return(resp.json())


class MountHandler(object):
    internal_mounts = ('identity', 'sys')

    def __init__(self, client, mounts_xml = None):
        self.client = client
        self.cubbyhandler = CubbyHandler(self.client)
        self.xml = mounts_xml
        self.mounts = {}
        self.paths = {}
        self.getSysMounts()

    def getMountType(self, mount):
        if not self.mounts:
            self.getSysMounts()
        mtype = self.mounts.get(mount)
        if not mtype:
            _logger.error('Mount not found in defined mounts')
            _logger.debug('The mount {0} was not found in the defined mounts.'.format(mount))
            raise ValueError('Mount not found in defined mounts')
        return(mtype)

    def getSecret(self, path, mount, version = None):
        pass

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

    def printer(self, output = None, indent = 4):
        # def treePrint(obj, s = 'Password Store\n', level = 0):
        #     prefix = '├──'
        #     leading_prefix = '│'
        #     last_prefix = '└──'
        #     pass
        #     return(s)
        if output:
            output = output.lower()
        if output and output not in ('pretty', 'yaml', 'json'):
        # if output and output not in ('pretty', 'yaml', 'json', 'tree'):
            _logger.error('Invalid output format')
            _logger.debug('The output parameter ("{0}") must be one of: pretty, yaml, json, or None'.format(output))
            # _logger.debug(('The output parameter ("{0}") must be one of: '
            #                'pretty, yaml, json, tree, or None').format(output))
            raise ValueError('Invalid output format')
        if output in ('pretty', 'yaml', 'json'):
            if not any(((indent is None), isinstance(indent, int))):
                _logger.error('indent parameter must be an integer or None')
                _logger.debug('The indent parameter ({0}) must be an integer or None'.format(indent))
                raise ValueError('indent parameter must be an integer or None')
        if not self.paths:
            self.getSecretsTree()
        if output == 'json':
            import json
            return(json.dumps(self.paths, indent = indent))
        elif output == 'yaml':
            import yaml  # https://pypi.org/project/PyYAML/
            # import pyaml  # https://pypi.python.org/pypi/pyaml
            return(yaml.dump(self.paths, indent = indent))
        elif output == 'pretty':
            import pprint
            if indent is None:
                indent = 1
            return(pprint.pformat(self.paths, indent = indent, width = shutil.get_terminal_size((80, 20)).columns))
        # elif output == 'tree':
        #     import tree  # TODO? Wayyy later.
        elif not output:
            return(str(self.paths))
        return(None)

    def search(self):
        pass
