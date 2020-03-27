import logging
import logging.handlers
import os
##
try:
    # https://www.freedesktop.org/software/systemd/python-systemd/journal.html#journalhandler-class
    from systemd import journal
    _has_journald = True
except ImportError:
    _has_journald = False


logfile = os.path.abspath(os.path.expanduser('~/.cache/vaultpass/vaultpass.log'))


def prepLogfile(path = logfile):
    path = os.path.abspath(os.path.expanduser(path))
    # Set up the permissions beforehand.
    os.makedirs(os.path.dirname(logfile), exist_ok = True, mode = 0o0700)
    if not os.path.isfile(path):
        # "Touch" it so the next command doesn't fail.
        with open(path, 'w') as fh:
            fh.write('')
    os.chmod(logfile, 0o0600)
    return(path)


_cfg_args = {'handlers': [],
             'level': logging.DEBUG}  # TEMPORARY FOR TESTING
if _has_journald:
    # There were some weird changes somewhere along the line.
    try:
        # But it's *probably* this one.
        h = journal.JournalHandler()
    except AttributeError:
        h = journal.JournaldLogHandler()
    # Systemd includes times, so we don't need to.
    h.setFormatter(logging.Formatter(style = '{',
                                     fmt = ('{name}:{levelname}:{name}:{filename}:'
                                            '{funcName}:{lineno}: {message}')))
    _cfg_args['handlers'].append(h)
# Logfile
h = logging.handlers.RotatingFileHandler(prepLogfile(),
                                         encoding = 'utf8',
                                         # Disable rotating for now.
                                         # maxBytes = 50000000000,
                                         # backupCount = 30
                                         )
h.setFormatter(logging.Formatter(style = '{',
                                 fmt = ('{asctime}:'
                                        '{levelname}:{name}:{filename}:'
                                        '{funcName}:{lineno}: {message}')))
_cfg_args['handlers'].append(h)

logging.basicConfig(**_cfg_args)
logger = logging.getLogger('VaultPass')

logger.info('Logging initialized.')
