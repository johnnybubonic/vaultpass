import argparse


_opers = ['cp', 'edit', 'find', 'generate', 'git', 'grep', 'help', 'init', 'insert', 'ls', 'mv', 'rm', 'show',
          'version', 'import']  # "import" is new


def parseArgs():
    args = argparse.ArgumentParser(description = 'VaultPass - a Vault-backed Pass replacement',
                                   prog = 'pass',
                                   epilog = ('This program has context-specific help. Try '))
    commonargs = argparse.ArgumentParser(add_help = False)
    commonargs.add_argument('-c', '--config',
                            default = '~/.config/vaultpass.xml',
                            help = ('The path to your configuration file. Default: ~/.config/vaultpass.xml'))

    args.add_argument('oper',
                      choices = _opers,
                      help = ('The operation to perform. Use the help operation or see the man page for more '
                              'information'))
    args.add_argument()
