import argparse
##
from . import constants


def parseArgs():
    args = argparse.ArgumentParser(description = 'VaultPass - a Vault-backed Pass replacement',
                                   prog = 'pass',
                                   epilog = ('This program has context-specific help. Try "... cp --help". '
                                             'This help output is intentionally terse; see "man 1 vaultpass" and the '
                                             'README for more complete information, configuration, and usage.'))
    args.add_argument('-c', '--config',
                      default = '~/.config/vaultpass.xml',
                      help = ('The path to your configuration file. Default: ~/.config/vaultpass.xml'))
    args.add_argument('-m', '--mount',
                      dest = 'mount',
                      required = False,
                      help = ('The mount to use in OPERATION. If not specified, assume all mounts we have access '
                              'to/all mounts specified in -c/--config'))
    # I wish argparse supported default subcommands. It doesn't as of python 3.8.
    subparser = args.add_subparsers(help = ('Operation to perform'),
                                    metavar = 'OPERATION',
                                    dest = 'oper')
    cp = subparser.add_parser('cp',
                              aliases = ['copy'])
    edit = subparser.add_parser('edit')
    find = subparser.add_parser('find',
                                aliases = ['search'])
    gen = subparser.add_parser('generate')
    git = subparser.add_parser('git')  # Dummy opt; do nothing
    grep = subparser.add_parser('grep')
    helpme = subparser.add_parser('help')
    initvault = subparser.add_parser('init')
    insertval = subparser.add_parser('insert',
                                     aliases = ['add'])
    ls = subparser.add_parser('ls',
                              aliases = ['list'])
    mv = subparser.add_parser('mv',
                              aliases = ['rename'])
    rm = subparser.add_parser('rm',
                              aliases = ['remove', 'delete'])
    show = subparser.add_parser('show')
    version = subparser.add_parser('version')
    importvault = subparser.add_parser('import')
    # CP/COPY
    cp.add_argument('-f', '--force',
                    dest = 'force',
                    action = 'store_true',
                    help = ('If specified, replace NEWPATH if it exists'))
    cp.add_argument('oldpath',
                    metavar = 'OLDPATH',
                    help = ('The original ("source") path for the secret'))
    cp.add_argument('newpath',
                    metavar = 'NEWPATH',
                    help = ('The new ("destination") path for the secret'))
    # EDIT
    edit.add_argument('-e', '--editor',
                      metavar = '/PATH/TO/EDITOR',
                      dest = 'editor',
                      default = constants.EDITOR,
                      help = ('The editor program to use (sourced from EDITOR environment variable). '
                              'Default: {0}').format(constants.EDITOR))
    edit.add_argument('path',
                      metavar = 'PATH_TO_SECRET',
                      help = ('Insert a new secret at PATH_TO_SECRET if it does not exist, otherwise edit it using '
                              'your default editor (see -e/--editor)'))
    # FIND/SEARCH
    find.add_argument('pattern',
                      metavar = 'NAME_PATTERN',
                      help = ('List secrets\' paths whose names match the regex NAME_PATTERN'))
    # GENERATE
    gen.add_argument('-n', '--no-symbols',
                     dest = 'symbols',
                     action = 'store_false',
                     help = ('If specified, generate a password with no non-alphanumeric chracters'))
    gen.add_argument('-c', '--clip',
                     dest = 'clip',
                     action = 'store_true',
                     help = ('If specified, do not print the password but instead place in the clipboard for '
                             'a given number of seconds (see -s/--seconds)'))
    gen.add_argument('-s', '--seconds',
                     dest = 'seconds',
                     type = int,
                     default = constants.CLIP_TIMEOUT,
                     help = ('If generating to the clipboard (see -c/--clip), clear the clipboard after this many '
                             'seconds. Default: {0}').format(constants.CLIP_TIMEOUT))
    gen.add_argument('-C', '--characters',
                     dest = 'chars',
                     default = constants.SELECTED_PASS_CHARS,
                     help = ('The characters to use when generating a password (symbols included). '
                             'Default: {0}').format(constants.SELECTED_PASS_CHARS))
    gen.add_argument('-Cn', '--characters-no-symbols',
                     dest = 'chars_plain',
                     default = constants.SELECTED_PASS_NOSYMBOL_CHARS,
                     help = ('The characters to use when generating an alphanumeric-only password, '
                             'Default: {0}').format(constants.SELECTED_PASS_NOSYMBOL_CHARS))
    # TODO: support?
    gen.add_argument('-i', '--in-place',
                     dest = 'in_place',
                     action = 'store_true',
                     help = ('(Unused; kept for compatibility reasons)'))
    gen.add_argument('-q', '--qrcode',
                     dest = 'qr',
                     action = 'store_true',
                     help = ('If specified, display the password as a QR code (graphically or in-terminal depending '
                             'on supported environment)'))
    gen.add_argument('-f', '--force',
                     dest = 'force',
                     help = ('If specified and PATH/TO/SECRET exists, overwrite without prompting first'))
    gen.add_argument('path',
                     metavar = 'PATH/TO/SECRET',
                     help = ('The path to the secret'))
    gen.add_argument('length',
                     type = int,
                     default = constants.GENERATED_LENGTH,
                     metavar = 'LENGTH',
                     help = ('The length (number of characters) in the generated password. '
                             'Default: {0}').format(constants.GENERATED_LENGTH))
    return(args)
