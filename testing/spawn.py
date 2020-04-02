#!/usr/bin/env python3

import json
import os
import re
import shutil
import socket
import subprocess
import time
##
import hvac
import psutil
from lxml import etree
##
from . import serverconf
from . import vauptpassconf


clientconf_file = './test.config.xml'


_url_re = re.compile(r'^(?P<proto>https?)://(?P<addr>[^:/]+)(:(?P<port>[0-9]+)?)?(?P<path>/.*)?$')


class VaultSpawner(object):
    client = hvac.Client()
    binary_name = 'vault'  # The name of the process, not a path!
    binary_path = binary_name  # Can be an absolute path; the binary Vault should be started via.
    client_conf = None
    cmd = None
    unseal = None
    is_running = None
    local = True
    pid = None

    def __init__(self, conf, genconf = True):
        self.conf = conf
        self.genconf = genconf
        self._parseConf()
        self._getCreds()
        self._connCheck()

    def _connCheck(self, bind = True):
        listener = self.conf['listener'][0]['tcp']
        addr = listener['address']
        is_not_tls = listener.get('tls_disable', False)
        url = '{0}://{1}'.format(('http' if is_not_tls else 'https'), addr)
        if not _url_re.search(url):
            raise ValueError('Invalid server address')
        self.client.url = url
        r = _url_re.search(self.client.url)
        if not r:
            raise ValueError('Invalid server URL')
        try:
            self.port = int(r.groupdict().get('port', 80))
        except ValueError:
            self.port = 80
        self.ip = socket.gethostbyname(r.groupdict()['addr'])
        sock = socket.socket()
        try:
            if bind:
                try:
                    sock.bind((self.ip, self.port))
                    self.pid = None
                    self.is_running = False
                except OSError as e:
                    if e.errno == 98:
                        self.is_running = True
                    elif e.errno == 99:
                        # The address isn't on this box.
                        self.local = False
                        self.pid = None
            sock.connect((self.ip, self.port))
            sock.close()
        except (ConnectionRefusedError, ConnectionAbortedError, ConnectionResetError):
            self.is_running = False
        finally:
            try:
                sock.close()
            except NameError:
                # No idea how we got here, but...
                pass
        return(None)

    def _getClientConf(self, fpath = clientconf_file):
        clientconf = os.path.abspath(os.path.expanduser(fpath))
        self.client_conf = vauptpassconf.getConfig(clientconf)
        return(None)

    def _getCreds(self, new_unseal = None, new_auth = None, write_conf = clientconf_file):
        self._getClientConf()
        rewrite_xml = False
        # TODO: finish regen of client conf and re-parse so new elements get added to both,
        #   and write out namespaced xml
        unseal_xml = self.client_conf.namespaced_xml.find('.//{0}unseal'.format(self.client_conf.xml.nsmap[None]))
        self.unseal = unseal_xml.text
        auth_xml = self.client_conf.xml.find('.//{0}auth'.format(self.client_conf.xml.nsmap[None]))
        token_xml = auth_xml.find('.//token')
        if unseal_xml is not None and not new_unseal:
            self.unseal = unseal_xml.text
        if token_xml is not None and not new_auth:
            self.client.token = token_xml.text
        if new_unseal:
            unseal_xml.getparent().replace(unseal_xml, new_unseal)
            rewrite_xml = True
        if new_auth:
            auth_xml.getparent().replace(auth_xml, new_auth)
            rewrite_xml = True
        if rewrite_xml:
            write_conf = os.path.abspath(os.path.expanduser(write_conf))
            with open(write_conf, 'w') as fh:
                fh.write()  # TODO: which object?
        return(None)

    def _getProcess(self):
        def clear():
            self.pid = None
            return(None)
        self._getCreds()
        if not self.local:
            clear()
            return(None)
        processes = [p for p in psutil.process_iter() if p.name() == self.binary_name]
        if not processes:
            clear()
            return(None)
        if self.is_running:
            if len(processes) != 1 and os.geteuid() != 0:
                # Vault hides its PID in the network connections/hides its FDs,
                # so we have *no* way to get the PID as a regular user.
                raise RuntimeError('Cannot determine Vault instance to manage')
            elif len(processes) == 1:
                self.pid = self.processes[0].pid
            else:
                # We're running as root.
                conns = [c for c in psutil.net_connections() if c.laddr.ip == ip and c.laddr.port == port]
                if not len(conns) == 1:
                    # This, theoretically, should never happen.
                    raise RuntimeError('Cannot determine Vault instance to manage')
                else:
                    self.pid = conns[0].pid
                    return(None)
        return(None)

    def _initChk(self):
        self._getClientConf()
        self._connCheck()
        if not self.is_running:
            return(False)
        if not self.client.sys.is_initialized():
            init_rslt = self.client.sys.initialize(secret_shares = 1, secret_threshold = 1)
            self.unseal = init_rslt['keys_base64'][0]
            self.client.token = init_rslt['root_token']
            newauth = etree.Element('auth')
            newtoken = etree.Element('token')
            newtoken.text = self.client.token
            newauth.append(newtoken)
            newunseal = etree.Element('unseal')
            newunseal.text = self.unseal
            self._getCreds(new_auth = newauth, new_unseal = newunseal)
        if self.client.sys.is_sealed():
            self.client.sys.submit_unseal_key(self.unseal)
        return(True)

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
        return(None)

    def start(self):
        self._getProcess()
        if self.is_running:
            # Already started.
            self._initChk()
            return(None)
        if not self.local:
            # It's a remote address
            self._initChk()
            return(None)
        cmd_str = [self.binary_path, 'server']
        cmd_str.extend(['-config', serverconf.conf_file])
        # We have to use Popen because even vault server doesn't daemonize.
        # Gorram it, HashiCorp.
        self.cmd = subprocess.Popen(cmd_str, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        if self.cmd.returncode != 0:
            print('STDERR:\n{0}'.format(self.cmd.stderr.decode('utf-8')))
            raise RuntimeError('Vault did not start correctly')
        attempts = 5
        seconds = 3
        while not self.is_running and attempts != 0:
            self._connCheck()
            time.sleep(seconds)
        if not self.is_running:
            raise TimeoutError('Could not start Vault')
        self._initChk()
        return(None)

