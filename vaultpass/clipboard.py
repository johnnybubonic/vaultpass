import base64
import json
import logging
import os
import pwd
import re
# We COULD use pyperclip or pygtk or whatever for this, but we have enough external deps already.
import subprocess
import sys
import time
import warnings
_logger = logging.getLogger()
##
import psutil
##
from . import constants


def getProc(display, clipboard):
    real_uid = pwd.getpwnam(os.getlogin()).pw_uid
    procs = []  # Normally I'd do this in a list comprehension but switching to a loop for readability.
    for p in psutil.process_iter(attrs = ['name', 'cmdline', 'environ', 'uids']):
        if p.name() != 'xclip':
            continue
        if p.uids().effective == real_uid:
            p_display = p.environ().get('DISPLAY')
            cbrd = None
            for idx, arg in enumerate(p.cmdline()):
                if arg.startswith('-se'):
                    cbrd = p.cmdline()[(idx + 1)]
                    break
            if p_display == display and cbrd == clipboard:
                return(p)
    return(None)


def pasteClipboard(data,
                   seconds = constants.CLIP_TIMEOUT,
                   clipboard = constants.CLIPBOARD,
                   printme = False,
                   *args, **kwargs):
    if clipboard not in constants.ALLOWED_CLIPBOARDS:
        _logger.error('Invalid clipboard name')
        _logger.debug(('The clipboard "{0}" is invalid. '
                       'Must be one of: {1}.').format(', '.join((clipboard, constants.ALLOWED_CLIPBOARDS))))
        raise ValueError('Invalid clipboard')
    if isinstance(data, dict):
        data = json.dumps(dict, indent = 4)
    if not isinstance(data, str):
        data = str(data)
    _logger.debug('Copying to clipboard {0} for {1} seconds'.format(clipboard, seconds))
    termname = os.environ.get('TERM', 'linux')
    if termname == 'linux':
        # We don't have X, so we have no usable xclip.
        _logger.warning('Disabling clipboard copying because we don\'t have X')
        return(None)
    display = os.environ.get('DISPLAY')
    if not display:
        # We don't have X, so we have no usable xclip.
        _logger.warning('Disabling clipboard copying because we don\'t have X')
        return(None)
    exists = getProc(display)
    current = None
    if exists:
        cmd = subprocess.run(['xclip',
                              '-out',
                              '-display', display,
                              '-selection', clipboard])
        current = cmd.stdout
        exists.kill()
    cmd = subprocess.run(['xclip',
                          '-display', display,
                          '-selection', clipboard],
                         input = data.encode('utf-8'),
                         stdout = subprocess.PIPE,
                         stderr = subprocess.PIPE)
    if cmd.returncode != 0:
        _logger.error('Could not write to clipboard')
        _logger.debug('Could not write to clipboard "{0}" on display {1}.'.format(clipboard, display))
        for x in ('stdout', 'stderr'):
            i = getattr(cmd, x)
            if i:
                i = i.decode('utf-8').strip()
                if i != '':
                    _logger.debug('{0}: {1}'.format(x.upper(), i))
        raise RuntimeError('Could not write to clipboard')
    if printme:
        print('Copied to clipboard "{0}".'.format(clipboard))
    if seconds is not None:
        if printme:
            print('Active for {0} seconds...'.format(seconds))
            for s in range(seconds, 0, -1):
                sys.stdout.write('{0} seconds remaining...'.format(s))
                sys.stdout.flush()
                time.sleep(1)
                sys.stdout.write('\r')
            print('\033[2KClipboard cleared.')
        else:
            for s in range(seconds, 0, -1):
                time.sleep(1)
        if current:
            cmd = subprocess.run(['xclip',
                                  '-display', display,
                                  '-selection', clipboard],
                                 input = current,
                                 stdout = subprocess.PIPE,
                                 stderr = subprocess.PIPE)
            if cmd.returncode != 0:
                _logger.warning('Could not restore clipboard')
                _logger.debug('Could not restore clipboard "{0}" on display {1}.'.format(clipboard, display))
                for x in ('stdout', 'stderr'):
                    i = getattr(cmd, x)
                    if i:
                        i = i.decode('utf-8').strip()
                        if i != '':
                            _logger.debug('{0}: {1}'.format(x.upper(), i))
                # We absolutely should warn about this.
                warnings.warn('Could not restore clipboard; secret remains in clipboard!')
        else:
            proc = getProc(display, clipboard)
            if not proc:
                _logger.warning('Could not restore clipboard')
                _logger.debug('Could not restore clipboard "{0}" on display {1}.'.format(clipboard, display))
                # We absolutely should warn about this.
                warnings.warn('Could not restore clipboard; secret remains in clipboard!')
            else:
                proc.kill()
    return(None)
