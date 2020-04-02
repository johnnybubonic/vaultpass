#!/usr/bin/env python3

import json
import os


conf_file = './testserver.json'
log_file = './vault.log'

default_conf = {'listener': [
                                {'tcp': {'address': '127.0.0.1:8200',
                                         'tls_disable': True}}
                            ],
                'storage': {'file': {'path': './data'}},
                'log_level': 'Debug',  # highest is 'Trace'
                'pid_file': './test.pid',
                'raw_storage_endpoint': True,
                'log_format': 'json',  # or String
                'ui': True}


conf_file = os.path.abspath(os.path.expanduser(conf_file))
log_file = os.path.abspath(os.path.expanduser(log_file))


def genConf(confdict = None):
    if not confdict:
        confdict = default_conf.copy()
    storage = confdict.get('storage')
    if storage:
        if 'file' in storage.keys():
            storage['file']['path'] = os.path.abspath(os.path.expanduser(storage['file']['path']))
            confdict['storage'] = storage
    if 'pid_file' in confdict:
        confdict['pid_file'] = os.path.abspath(os.path.expanduser(confdict['pid_file']))
    conf = os.path.abspath(os.path.expanduser(conf_file))
    with open(conf, 'w') as fh:
        fh.write(json.dumps(confdict, indent = 4))
    return(None)


def parseHCL(hclcontent):
    # We only load this on-demand.
    import hcl
    conf = hcl.loads(hclcontent)
    return(conf)


if __name__ == '__main__':
    genConf()
