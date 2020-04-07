import argparse
import os
##
from . import constants


def parseArgs():
    args = argparse.ArgumentParser(description = 'VaultPass - a Vault-backed Pass replacement',
                                   prog = constants.NAME,
                                   epilog = ('This program has context-specific help. Try "... cp --help". '
                                             'This help output is intentionally terse; see "man 1 vaultpass" and the '
                                             'README for more complete information, configuration, and usage.'))
    args.add_argument('-V', '--version',
                      action = 'version',
                      version = '{0} {1}'.format(constants.NAME, constants.VERSION))
    args.add_argument('-c', '--config',
                      default = '~/.config/vaultpass.xml',
                      help = ('The path to your configuration file. Default: ~/.config/vaultpass.xml'))
    args.add_argument('-m', '--mount',
                      dest = 'mount',
                      default = 'secret',
                      help = ('The mount to use in OPERATION. If not specified, assume a mount named "secret"'))
    # I wish argparse supported default subcommands. It doesn't as of python 3.8.
    subparser = args.add_subparsers(help = ('Operation to perform'),
                                    metavar = 'OPERATION',
                                    dest = 'oper')
    cp = subparser.add_parser('cp',
                              description = ('Copy a secret from one path to another'),
                              help = ('Copy a secret from one path to another'),
                              aliases = ['copy'])
    edit = subparser.add_parser('edit',
                                description = ('Edit an existing secret or create it if it does not exist'),
                                help = ('Edit an existing secret or create it if it does not exist'))
    find = subparser.add_parser('find',
                                description = ('Find the path to a secret given a regex of the name'),
                                help = ('Find the path to a secret given a regex of the name'),
                                aliases = ['search'])
    gen = subparser.add_parser('generate',
                               description = ('Generate a password/passphrase'),
                               help = ('Generate a password/passphrase'))
    # Dummy opt; do nothing
    git = subparser.add_parser('git',
                               description = ('This operation does nothing except maintain compatibility'))
    grep = subparser.add_parser('grep',
                                description = ('Search secret content by regex'),
                                help = ('Search secret content by regex'))
    # This just does the same as -h/--help.
    helpme = subparser.add_parser('help',
                                  description = ('Show this help and exit'),
                                  help = ('Show this help and exit'))
    initvault = subparser.add_parser('init',
                                     description = ('This operation does nothing except maintain compatibility'),
                                     help = ('This operation does nothing except maintain compatibility'))
    insertval = subparser.add_parser('insert',
                                     description = ('Add a new secret (or overwrite one)'),
                                     help = ('Add a new secret (or overwrite one)'),
                                     aliases = ['add'])
    ls = subparser.add_parser('ls',
                              description = ('List names of secrets available'),
                              help = ('List names of secrets available'),
                              aliases = ['list'])
    mv = subparser.add_parser('mv',
                              description = ('Moves a secret to a different path'),
                              help = ('Moves a secret to a different path'),
                              aliases = ['rename', 'move'])
    rm = subparser.add_parser('rm',
                              description = ('Delete a secret'),
                              help = ('Delete a secret'),
                              aliases = ['remove', 'delete'])
    show = subparser.add_parser('show',
                                description = ('Print/fetch a secret'),
                                help = ('Print/fetch a secret'))
    version = subparser.add_parser('version',
                                   description = ('Print the VaultPass version and exit'),
                                   help = ('Print the VaultPass version and exit'))
    importvault = subparser.add_parser('import',
                                       description = ('Import your existing Pass into Vault'),
                                       help = ('Import your existing Pass into Vault'))
    # CP/COPY
    # vp.copySecret()
    cp.add_argument('-f', '--force',
                    dest = 'force',
                    action = 'store_true',
                    help = ('If specified, replace NEWPATH if it exists'))
    cp.add_argument('-m', '--mount',
                    dest = 'newmount',
                    nargs = 1,
                    required = False,
                    help = ('The mount for the destination. Default is to use the main command\'s -m/--mount'))
    cp.add_argument('oldpath',
                    metavar = 'OLDPATH',
                    help = ('The original ("source") path for the secret'))
    cp.add_argument('newpath',
                    metavar = 'NEWPATH',
                    help = ('The new ("destination") path for the secret'))
    # EDIT
    # vp.editSecret()
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
    # vp.searchSecretNames()
    find.add_argument('pattern',
                      metavar = 'NAME_PATTERN',
                      help = ('List secrets\' paths whose names match the regex NAME_PATTERN'))
    # GENERATE
    # vp.generateSecret()
    # TODO: feature parity with passgen (spaces? etc.)
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
                             'Default: {0}').format(constants.SELECTED_PASS_CHARS.replace('%', '%%')))
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
                     nargs = '?',
                     metavar = 'LENGTH',
                     help = ('The length (number of characters) in the generated password. '
                             'Default: {0}').format(constants.GENERATED_LENGTH))
    # GIT
    git.add_argument('dummy_opts',
                     nargs = '+',
                     default = None,
                     metavar = 'dummy',
                     help = ('(Unused; kept for compatibility reasons)'))
    # GREP
    # vp.searchSecrets()
    # I wish argparse supported arbitrary arguments.
    # It *KIND* of does: https://stackoverflow.com/a/37367814/733214 but then I wouldn't be able to properly grab the
    # regex pattern without more hackery. So here's to wasting my life.
    ## DUMMY OPTIONS ##
    ####################################################################################################################
    grep.add_argument('-V', '--version',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-E', '--extended-regexp',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-F', '--fixed-strings',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-G', '--basic-regexp',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-P', '--perl-regexp',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-i', '--ignore_case',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('--no-ignore-case',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-v', '--invert-match',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-w', '--word-regexp',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-x', '--line-regexp',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-y',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-c', '--count',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-L', '--files-without-match',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-l', '--files-with-matches',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-o', '--only-matching',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-q', '--quiet', '--silent',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-s', '--no-messages',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-b', '--byte-offset',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-H', '--with-filename',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-n', '--line-number',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-T', '--initial-tab',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-u', '--unix-byte-offsets',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-Z', '--null',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-a', '--text',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-I',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-r', '--recursive',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-R', '--dereference-recursive',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('--line-buffered',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-U', '--binary',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-z', '--null-data',
                      action = 'store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-e', '--regexp',
                      dest = 'dummy_0',
                      metavar = 'PATTERNS',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-f', '--file',
                      dest = 'dummy_1_0',
                      metavar = 'FILE',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('--exclude-from',
                      dest = 'dummy_1_1',
                      metavar = 'FILE',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-m', '--max-count',
                      dest = 'dummy_2_0',
                      metavar = 'NUM',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-A', '--after-context',
                      dest = 'dummy_2_1',
                      metavar = 'NUM',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-B', '--before-context',
                      dest = 'dummy_2_2',
                      metavar = 'NUM',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-C', '--context',
                      dest = 'dummy_2_3',
                      metavar = 'NUM',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('--label',
                      dest = 'dummy_3',
                      metavar = 'LABEL',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('--binary-files',
                      dest = 'dummy_4',
                      metavar = 'TYPE',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-D', '--devices',
                      dest = 'dummy_5_0',
                      metavar = 'ACTION',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-d', '--directories',
                      dest = 'dummy_5_1',
                      metavar = 'ACTION',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('--exclude',
                      dest = 'dummy_6_0',
                      metavar = 'GLOB',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('--exclude-dir',
                      dest = 'dummy_6_1',
                      metavar = 'GLOB',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('--include',
                      dest = 'dummy_6_2',
                      metavar = 'GLOB',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('--color', '--colour',
                      dest = 'dummy_7',
                      metavar = 'WHEN',
                      const = None,
                      nargs = '?',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    ####################################################################################################################
    grep.add_argument('pattern',
                      metavar = 'REGEX_PATTERN',
                      help = ('Regex pattern to search passwords'))
    # HELP has no arguments.
    # INIT
    # vp.initVault()
    initvault.add_argument('-p', '--path',
                           dest = 'path',
                           help = ('(Dummy option; kept for compatibility reasons)'))
    initvault.add_argument('gpg_id',
                           dest = 'gpg_id',
                           help = ('(Dummy option; kept for compatibility reasons)'))
    # INSERT
    # vp.insertSecret()
    # TODO: if -e/--echo is specified and sys.stdin, use sys.stdin rather than prompt
    insertval.add_argument('-e', '--echo',
                           dest = 'allow_shouldersurf',
                           action = 'store_true',
                           help = ('If specified, enable keyboard echo (show the secret as it\'s being typed) and '
                                   'disable confirmation'))
    insertval.add_argument('-m', '--multiline',
                           action = 'store_true',
                           dest = 'multiline',
                           help = ('If specified, keep reading stdin until EOF is reached or ctrl-d is pressed'))
    insertval.add_argument('-f', '--force',
                           action = 'store_true',
                           help = ('If specified, overwrite any existing secret without prompting'))
    insertval.add_argument('-n', '--no-confirm',
                           dest = 'confirm',
                           action = 'store_false',
                           help = ('If specified, disable password prompt confirmation. '
                                   'Has no effect if -e/--echo is specified'))
    insertval.add_argument('path',
                           metavar = 'PATH/TO/SECRET',
                           help = ('The path to the secret'))
    # LS
    # vp.listSecretNames()/vp.mount.print() ?
    ls.add_argument('-o', '--output',
                    dest = 'output',
                    choices = constants.SUPPORTED_OUTPUT_FORMATS,
                    metavar = 'OUTPUT_FORMAT',
                    help = ('The format to output the hierarchy in. '
                            'If specified, must be one of: {0} '
                            '(the default is a condensed python '
                            'dict repr)').format(', '.join(constants.SUPPORTED_OUTPUT_FORMATS)))
    ls.add_argument('-i', '--indent',
                    type = int,
                    default = 4,
                    dest = 'indent',
                    help = ('If -o/--output is "pretty", "yaml", or "json", specify the indent level. '
                            'Default is 4'))
    ls.add_argument('path',
                    metavar = 'PATH/TO/TREE/BASE',
                    help = ('List names of secrets recursively, starting at PATH/TO/TREE/BASE'))
    # MV
    # vp.copySecret(remove_old = True)
    mv.add_argument('-f', '--force',
                    dest = 'force',
                    action = 'store_true',
                    help = ('If specified, replace NEWPATH if it exists'))
    mv.add_argument('oldpath',
                    metavar = 'OLDPATH',
                    help = ('The original ("source") path for the secret'))
    mv.add_argument('newpath',
                    metavar = 'NEWPATH',
                    help = ('The new ("destination") path for the secret'))
    # RM
    # vp.deleteSecret()
    # Is this argument even sensible since it isn't a filesystem?
    rm.add_argument('-r', '--recursive',
                    dest = 'recurse',
                    action = 'store_true',
                    help = ('If PATH/TO/SECRET is a directory, delete all subentries'))
    rm.add_argument('-f', '--force',
                    dest = 'force',
                    action = 'store_true',
                    help = ('If specified, delete all matching path(s) without prompting for confirmation'))
    rm.add_argument('path',
                    metavar = 'PATH/TO/SECRET',
                    help = ('The path to the secret or subdirectory'))
    # SHOW
    # vp.getSecret(printme = True)
    # TODO: does the default overwrite the None if not specified?
    show.add_argument('-c', '--clip',
                      nargs = '?',
                      type = int,
                      default = constants.SHOW_CLIP_LINENUM,
                      metavar = 'LINE_NUMBER',
                      dest = 'clip',
                      help = ('If specified, copy line number LINE_NUMBER (Default: {0}) from the secret to the '
                              'clipboard instead of printing it. '
                              'Use 0 for LINE_NUMBER for the entire secret').format(constants.SHOW_CLIP_LINENUM))
    show.add_argument('-q', '--qrcode',
                      dest = 'qr',
                      nargs = '?',
                      type = int,
                      metavar = 'LINE_NUMBER',
                      default = None,
                      help = ('If specified, do not print the secret but instead generate a QR code of it (either '
                              'graphically or in-terminal depending on environment). '
                              'LINE_NUMBER has no effect and is kept for compatibility reasons'))
    show.add_argument('-s', '--seconds',
                      dest = 'seconds',
                      type = int,
                      default = constants.CLIP_TIMEOUT,
                      help = ('If copying to the clipboard (see -c/--clip), clear the clipboard after this many '
                              'seconds. Default: {0}').format(constants.CLIP_TIMEOUT))
    show.add_argument('path',
                      metavar = 'PATH/TO/SECRET',
                      help = ('The path to the secret'))
    # VERSION has no args.
    # IMPORT
    # vp.convert()
    importvault.add_argument('-d', '--directory',
                             default = constants.PASS_DIR,
                             metavar = '/PATH/TO/PASSWORD_STORE/DIR',
                             dest = 'pass_dir',
                             help = ('The path to your Pass data directory. Default: {0}').format(constants.PASS_DIR))
    importvault.add_argument('-H', '--gpg-homedir',
                             default = constants.GPG_HOMEDIR,
                             dest = 'gpghome',
                             metavar = '/PATH/TO/GNUPG/HOMEDIR',
                             help = ('The GnuPG "homedir". It MUST contain the private key that Pass uses. '
                                     'Default: {0}').format(constants.GPG_HOMEDIR))
    importvault.add_argument('-f', '--force',
                             dest = 'force',
                             action = 'store_true',
                             help = ('If specified, overwrite the destination in Vault.'))
    importvault.add_argument('mount',
                             metavar = 'MOUNT_NAME',
                             help = 'The mount name in Vault to import into (Pass\' hierarchy will be recreated). '
                                    'This mount MUST exist first and MUST be KV2 if auth is provided that does not '
                                    'have CREATE access on /sys/mounts!')
    return(args)
