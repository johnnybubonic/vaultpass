import logging
import re
import warnings
##
import dpath  # https://pypi.org/project/dpath/
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

    def read_secret(self, *args, **kwargs):
        # https://github.com/hashicorp/vault/issues/8644
        _logger.warning('Cannot get path info from a cubbyhole')
        return({'data': {}})


class MountHandler(object):
    internal_mounts = ('identity', 'sys')

    def __init__(self, client, mounts_xml = None):
        self.client = client
        self.cubbyhandler = CubbyHandler(self.client)
        self.xml = mounts_xml
        self.mounts = {}
        self.paths = {}
        self.getSysMounts()

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
        # TODO: should I blindly merge in instead or no?
        if self.xml:
            for mount in self.xml.findall('.//mount'):
                mname = mount.text
                mtype = mount.attrib.get('type', 'kv2')
                if mname not in self.mounts.keys():
                    self.mounts[mname] = mtype
                    _logger.debug('Added mountpoint {0} to mounts list with type {1}'.format(mount, mtype))
        return(None)

    def getSecrets(self, path = '/', mounts = None):
        if not mounts:
            mounts = self.mounts
        if isinstance(mounts, dict):
            mounts = list(mounts.keys())
        if not isinstance(mounts, list):
            mounts = [mounts]
        for mount in mounts:
            mtype = self.mounts.get(mount)
            if not mtype:
                _logger.error('Mount not found in defined mounts')
                _logger.debug('The mount {0} was not found in the defined mounts.'.format(mount))
                raise ValueError('Mount not found in defined mounts')
            handler = None
            if mtype == 'cubbyhole':
                handler = self.cubbyhandler
            elif mtype == 'kv':
                handler = self.client.secrets.kv.v1
            elif mtype == 'kv2':
                handler = self.client.secrets.kv.v2
            if mount not in self.paths.keys():
                self.paths[mount] = {}
            try:
                paths = handler.list_secrets(path = path, mount_point = mount)
            except hvac.exceptions.InvalidPath:
                _logger.error('Path does not exist')
                _logger.debug('Path {0} on mount {1} does not exist.'.format(path, mount))
                continue
            if 'data' not in paths.keys() or 'keys' not in paths['data'].keys():
                _logger.warning('Mount has no secrets/subdirs')
                _logger.debug('The mount {0} has no secrets or subdirectories'.format(mount))
                warnings.warn('Mount has no secrets/subdirs')
            for p2 in paths['data']['keys']:
                is_dir = False
                fullpath = '/'.join((path, p2)).replace('//', '/')
                if p2.endswith('/'):
                    r = _mount_re.search(fullpath)
                    fullpath = r.group('mount')
                    is_dir = True
                    self.paths[mount][fullpath] = None
                    self.getSecrets(path = p2, mounts = mount)
                sep_p2 = [i for i in fullpath.split('/') if i.strip() != '']
                if is_dir:
                    pass
                # print(mount, sep_p2)


    def print(self):
        import pprint
        pprint.pprint(self.paths)
        return(None)

    def search(self):
        pass
