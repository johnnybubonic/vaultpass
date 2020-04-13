import json
import logging
import subprocess
import tempfile
_logger = logging.getLogger()
##
from . import constants


def Editor(data, editor = constants.EDITOR, *args, **kwargs):
    if isinstance(data, dict):
        data = json.dumps(dict, indent = 4)
    if not isinstance(data, str):
        data = str(data)
    _logger.debug('Spawning edit instance.')
    fpath = tempfile.mkstemp(prefix = '.vaultpass.edit.', suffix = '.json', dir = '/dev/shm')[1]
    _logger.debug('Writing secret to {0} for editing.'.format(fpath))
    with open(fpath, 'w') as fh:
        fh.write(data)
    # We want this to block.
    cmd = subprocess.run([editor, fpath], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    if cmd.returncode != 0:
        _logger.error('{0} returned non-zero status code'.format(editor))
        for x in ('stdin', 'stdout'):
            o = getattr(cmd, x)
            if not o:
                continue
            o = o.decode('utf-8').strip()
            if o != '':
                _logger.debug('{0}: {1}'.format(x.upper(), o))
    with open(fpath, 'r') as fh:
        rawdata = fh.read()
    try:
        data = json.loads(rawdata)
    except (json.decoder.JSONDecodeError, TypeError):
        data = rawdata
    return(data, fpath)
