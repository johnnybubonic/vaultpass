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
    # I wish argparse supported arbitrary arguments.
    # It *KIND* of does: https://stackoverflow.com/a/37367814/733214 but then I wouldn't be able to properly grab the
    # regex pattern without more hackery. So here's to wasting my life.
    ## DUMMY OPTIONS ##
    ####################################################################################################################
    grep.add_argument('-V', '--version',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-E', '--extended-regexp',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-F', '--fixed-strings',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-G', '--basic-regexp',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-P', '--perl-regexp',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-i', '--ignore_case',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('--no-ignore-case',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-v', '--invert-match',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-w', '--word-regexp',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-x', '--line-regexp',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-y',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-c', '--count',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-L', '--files-without-match',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-l', '--files-with-matches',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-o', '--only-matching',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-q', '--quiet', '--silent',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-s', '--no-messages',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-b', '--byte-offset',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-H', '--with-filename',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-n', '--line-number',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-T', '--initial-tab',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-u', '--unix-byte-offsets',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-Z', '--null',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-a', '--text',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-I',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-r', '--recursive',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-R', '--dereference-recursive',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('--line-buffered',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-U', '--binary',
                      action='store_true',
                      help = ('(Dummy option; kept for compatibility reasons)'))
    grep.add_argument('-z', '--null-data',
                      action='store_true',
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

    return(args)
