#!/usr/bin/env python3

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import time
##
import hvac
import hvac.exceptions
import psutil
from lxml import etree
##
import serverconf
from vaultpass import config as vaultpassconf


_url_re = re.compile(r'^(?P<proto>https?)://(?P<addr>[^:/]+)(:(?P<port>[0-9]+)?)?(?P<path>/.*)?$')
_default_client_conf = './test.config.xml'


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
    is_new = False
    ip = None
    port = None

    def __init__(self, conf, genconf = True, clientconf_file = None, test_data = True, *args, **kwargs):
        self.conf = conf
        self.genconf = genconf
        if clientconf_file:
            self.clientconf_file = clientconf_file
        else:
            fpath = os.path.abspath(os.path.expanduser(_default_client_conf))
            fname = os.path.split(fpath)[-1]
            loc_fpath = os.path.abspath(os.path.expanduser('./local.{0}'.format(fname)))
            if os.path.isfile(loc_fpath):
                self.clientconf_file = loc_fpath
            else:
                self.clientconf_file = fpath
        self.test_data = test_data  # TODO
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
            if is_not_tls:
                self.port = 80
            else:
                self.port = 443
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
                        # Already in use
                        self.is_running = True
                    elif e.errno == 99:
                        # The address isn't on this box.
                        self.local = False
                        self.pid = None
                finally:
                    sock.close()
                    sock = socket.socket()
            sock.connect((self.ip, self.port))
            sock.close()
            self.is_running = True
        except (ConnectionRefusedError, ConnectionAbortedError, ConnectionResetError) as e:
            self.is_running = False
        finally:
            try:
                sock.close()
            except NameError:
                # No idea how we got here, but...
                pass
        return(None)

    def _getClientConf(self, fpath = None):
        if not fpath:
            fpath = self.clientconf_file
        clientconf = os.path.abspath(os.path.expanduser(fpath))
        self.client_conf = vaultpassconf.getConfig(clientconf)
        return(None)

    def _getCreds(self, new_unseal = False, new_token = False, write_conf = None):
        if not write_conf:
            write_conf = self.clientconf_file
        self._getClientConf()
        rewrite_xml = False
        xml = self.client_conf.xml
        ns_xml = self.client_conf.namespaced_xml
        nsmap = ns_xml.nsmap
        unseal_ns_xml = ns_xml.find('.//{{{0}}}unseal'.format(nsmap[None]))
        unseal_xml = xml.find('.//unseal')
        auth_ns_xml = ns_xml.find('.//{{{0}}}auth'.format(nsmap[None]))
        auth_xml = xml.find('.//auth')
        token_ns_xml = auth_ns_xml.find('.//{{{0}}}token'.format(nsmap[None]))
        token_xml = auth_xml.find('.//token')
        if not new_unseal:
            self.unseal = unseal_xml.text
        else:
            unseal_xml.text = self.unseal
            unseal_ns_xml.text = self.unseal
            rewrite_xml = True
        if not new_token:
            self.client.token = token_xml.text
        else:
            token_xml.text = self.client.token
            token_ns_xml.text = self.client.token
            rewrite_xml = True
        if rewrite_xml:
            write_conf = os.path.abspath(os.path.expanduser(write_conf))
            with open(write_conf, 'wb') as fh:
                fh.write(self.client_conf.toString())
        return(None)

    def _getProcess(self):
        # TODO: check for pidfile in self.conf and read if file exists
        def clear():
            self.pid = None
            return(None)
        self._getCreds()
        self._connCheck(bind = False)
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
                self.pid = processes[0].pid
            else:
                # We're running as root.
                conns = [c for c in psutil.net_connections() if c.laddr.ip == self.ip and c.laddr.port == self.port]
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
            self._getCreds(new_token = True, new_unseal = True)
            self.is_new = True
        if self.client.sys.is_sealed():
            self.client.sys.submit_unseal_key(self.unseal)
        return(True)

    def _parseConf(self):
        is_hcl = False
        rawconf = None
        if not self.conf:
            if os.path.isfile(serverconf.conf_file):
                with open(serverconf.conf_file, 'r') as fh:
                    self.conf = json.loads(fh.read())
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

    def cleanup(self):
        self._connCheck(bind = False)
        if self.is_running:
            return(None)
        storage = self.conf.get('storage', {}).get('file', {}).get('path')
        if not storage:
            return(None)
        storage = os.path.abspath(os.path.expanduser(storage))
        if os.path.isdir(storage):
            shutil.rmtree(storage)
        return(None)

    def populate(self, strict = False):
        mounts = {}
        if not self.is_running:
            self.start()
        if not self.is_new and strict:
            return(None)
        if self.is_new:
            opts = {'file_path': serverconf.log_file,
                    'log_raw': True,
                    'hmac_accessor': False}
            self.client.sys.enable_audit_device(device_type = 'file',
                                                description = 'Testing log',
                                                options = opts)
        mount_xml = self.client_conf.xml.find('.//mount')
        if mount_xml is not None:
            for mount in mount_xml:
                mtype = mount.attrib.get('type', 'kv2')
                mounts[mount.text] = mtype
        else:
            # Use a default set.
            mounts['cubbyhole'] = 'cubbyhole'
            mounts['secret'] = 'kv2'
            mounts['secret_legacy'] = 'kv1'
        for idx, (mname, mtype) in enumerate(mounts.items()):
            opts = {}
            orig_mtype = mtype
            if mtype.startswith('kv'):
                opts = {'version': re.sub(r'^kv([0-9]+)$', r'\g<1>', mtype)}
                mtype = 'kv'
            try:
                self.client.sys.enable_secrets_engine(mtype,
                                                      path = mname,
                                                      description = 'Testing mount ({0})'.format(mtype),
                                                      options = opts)
                # We might have some issues writing secrets on fast machines.
                time.sleep(2)
            except hvac.exceptions.InvalidRequest as e:
                # It probably already exists.
                print('Exception creating {0}: {1} ({2})'.format(mname, e, e.__class__))
                print(opts)
            if orig_mtype not in ('kv1', 'kv2', 'cubbyhole'):
                continue
            args = {'path': 'test_secret{0}/foo{1}'.format(idx, mname),
                    'mount_point': mname,
                    'secret': {'bar{0}'.format(idx): 'baz'}}
            handler = None
            if orig_mtype == 'cubbyhole':
                handler = self.client.write
                args['path'] = '{0}/test_secret{1}'.format(mname, idx)
                args['foo_{0}'.format(mname)] = 'bar{0}'.format(idx)
                del(args['mount_point'])
                del(args['secret'])
            elif orig_mtype == 'kv1':
                handler = self.client.secrets.kv.v1.create_or_update_secret
            elif orig_mtype == 'kv2':
                handler = self.client.secrets.kv.v2.create_or_update_secret
            try:
                resp = handler(**args)
            except hvac.exceptions.InvalidPath:
                print('{0} path invalid'.format(args['path']))
            except Exception as e:
                print('Exception creating {0} on {1}: {2} ({3})'.format(args['path'], args['mount_point'], e, e.__class__))
                print(args)
        return(None)

    def start(self):
        self._getProcess()
        if self.is_running or not self.local:
            # Already started.
            self._initChk()
            return(None)
        cmd_str = [self.binary_path, 'server',
                   '-config', serverconf.conf_file]
        # We have to use .Popen() instead of .run() because even "vault server" doesn't daemonize.
        # Gorram it, HashiCorp.
        self.cmd = subprocess.Popen(cmd_str, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        attempts = 5
        seconds = 5
        while attempts > 0:
            self._connCheck(bind = False)
            if self.is_running:
                break
            time.sleep(seconds)
            attempts -= 1
        if not self.is_running:
            stdout = self.cmd.stdout.read().decode('utf-8').strip()
            stderr = self.cmd.stdout.read().decode('utf-8').strip()
            for x in ('stdout', 'stderr'):
                if locals()[x] != '':
                    print('{0}:\n{1}'.format(x.upper(), locals()[x]))
            self.cmd.kill()
            del(self.cmd)
            self.cmd = None
            raise TimeoutError('Could not start Vault')
        time.sleep(2)  # We need to make sure we give enough time for it to start up
        self._initChk()
        return(None)

    def stop(self):
        self._getProcess()
        if self.cmd:
            self.cmd.kill()
        else:
            if self.pid:
                import signal
                os.kill(self.pid, signal.SIGKILL)
        return(None)


def parseArgs():
    args = argparse.ArgumentParser(description = 'Start/Stop a test Vault instance and ensure sample data exists')
    args.add_argument('-n', '--no-test-data',
                      dest = 'test_data',
                      action = 'store_false',
                      help = ('If specified, do not populate with test data (if it doesn\'t exist)'))
    args.add_argument('-d', '--delete',
                      dest = 'delete_storage',
                      action = 'store_true',
                      help = ('If specified, delete the storage backend first so a fresh instance is created'))
    args.add_argument('-c', '--cleanup',
                      dest = 'cleanup',
                      action = 'store_true',
                      help = ('If specified, remove the storage backend when stopping'))
    args.add_argument('-s', '--server-conf',
                      dest = 'conf',
                      help = ('Specify a path to an alternate server configuration file. '
                              'If not provided, a default one will be used'))
    args.add_argument('-C', '--client-conf',
                      # default = './test.config.xml',
                      dest = 'clientconf_file',
                      help = ('Path to a vaultpass.xml to use. Default: ./test.config.xml'))
    args.add_argument('oper',
                      choices = ['start', 'stop'],
                      help = ('Operation to perform. One of: start, stop'))
    return(args)


def main():
    args = parseArgs().parse_args()
    s = VaultSpawner(**vars(args))
    if args.delete_storage:
        s.cleanup()
    if args.oper == 'start':
        s.start()
        if args.test_data:
            s.populate()
    elif args.oper == 'stop':
        s.stop()
        if args.cleanup:
            time.sleep(2)
            s.cleanup()
    return(None)


if __name__ == '__main__':
    main()
