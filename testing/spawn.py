#!/usr/bin/env python3

import json
import os
import re
import socket
import subprocess
##
import hvac
import psutil
##
from . import serverconf
from . import vauptpassconf


_url_re = re.compile(r'^(?P<proto>https?)://(?P<addr>[^:/]+)(:(?P<port>[0-9]+)?)?(?P<path>/.*)?$')


class VaultSpawner(object):
    client = hvac.Client()
    binary_name = 'vault'

    def __init__(self, conf, genconf = True, is_dev = False):
        self.conf = conf
        self.genconf = genconf
        self.pid = None
        self.process = None
        self._parseConf()

    def _getProcess(self):
        processes = [p for p in psutil.process_iter() if p.name() == self.binary_name]
        if not processes:
            self.process = None
            self.pid = None
            return(None)
        r = _url_re.search(self.client.url)
        if not r:
            raise ValueError('Invalid server URL')
        try:
            port = int(r.groupdict().get('port', 8200))
        except ValueError:
            port = 8200
        ip = socket.gethostbyname(r.groupdict('addr'))
        pids = []
        # First we try the easy way, but requires root privs even if you ran vault as your current user.
        has_priv = True
        for p in processes:
            pids.append(p)
            try:
                p_port = p.connections()
            except (psutil.AccessDenied, psutil.AccessDenied):
                has_priv = False
                break
        if not has_priv:
            conns = [c for c in psutil.net_connections() if c.laddr.port == port and c.laddr.ip == ip]
            if not conns:
                self.process = None
                self.pid = None
                return(None)
            for c in conns:
                if not c.pid:
                    continue
                if c.pid in pids:
                    self.pid = c.pid
                    self.process = psutil.Process(pid = self.pid)
            if not all((self.process, self.pid)):
                if len(conns) == 1 and len(pids) == 1:
                    self.process = pids[0]
                    self.pid = self.process.pid
                else:
                    raise RuntimeError('Could not reliably determine which Vault instance to manage')



    def _parseConf(self):
        is_hcl = False
        rawconf = None
        if not self.conf:
            if os.path.isfile(serverconf.conf_file):
                self.conf = serverconf.conf_file
            else:
                # Use the default.
                self.genconf = True
                self.conf = serverconf.default_conf
        elif not isinstance(self.conf, dict):
            # Assume it's a file.
            self.conf = os.path.abspath(os.path.expanduser(self.conf))
            with open(self.conf, 'r') as fh:
                rawconf = fh.read()
            try:
                self.conf = json.loads(rawconf)
            except json.decoder.JSONDecodeError:
                is_hcl = True  # It's probably HCL.
        if is_hcl:
            self.conf = serverconf.parseHCL(rawconf)
        if self.genconf:
            serverconf.genConf(confdict = self.conf)
        listener = self.conf['listener'][0]['tcp']
        addr = listener['address']
        is_tls = listener.get('tls_disable', False)
        url = '{0}://{1}'.format(('https' if is_tls else 'http'), addr)
        if not _url_re.search(url):
            raise ValueError('Invalid server address')
        self.client.url = url
        return(None)

    def start(self):
        if any((self.pid, self.process)):
            # Already started.
            return(None)
