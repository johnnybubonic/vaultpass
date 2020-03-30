import logging
import re
import warnings
##
import hvac.exceptions


_logger = logging.getLogger()
_mount_re = re.compile(r'^(?P<mount>.*)/')


class MountHandler(object):
    internal_mounts = ('identity', 'sys')

    def __init__(self, client, mounts_xml = None):
        self.client = client
        self.xml = mounts_xml
        self.mounts = []

    def getSysMounts(self):
        try:
            for mount, mount_info in self.client.sys.list_mounted_secrets_engines()['data'].items():
                r = _mount_re.search(mount)
                if r:
                    mount = r.group('mount')
                if mount in self.internal_mounts:
                    continue
                self.mounts.append(mount)
                _logger.debug('Added mountpoint to mounts list: {0}'.format(mount))
        except hvac.exceptions.Forbidden:
            _logger.warning('Client does not have permission to read /sys/mounts.')
        # TODO: xml parsing

        return(None)

    def print(self):
        pass

    def search(self):
        pass
