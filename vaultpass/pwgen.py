# Thanks to https://gist.github.com/stantonk/7268449
# See also:
# http://stackoverflow.com/questions/5480131/will-python-systemrandom-os-urandom-always-have-enough-entropy-for-good-crypto
import argparse
import random
import re
import warnings
##
from . import constants
##
try:
    import passlib.context
    import passlib.hash
    has_passlib = True
except ImportError:
    # TODO: adler32 and crc32 via zlib module?
    import hashlib
    has_passlib = False


if has_passlib:
    supported_hashes = tuple(i for i in dir(passlib.hash) if not i.startswith('_'))
else:
    supported_hashes = tuple(hashlib.algorithms_available)

# By default, complex is symbols and mixed-case alphanumeric. simple is mixed-case alphanumeric.
charsets = {'simple': constants.ALPHANUM_PASS_CHARS,
            'complex': constants.ALL_PASS_CHARS}


class genPass(object):
    def __init__(self,
                 case = None,
                 charset = 'complex',
                 chars = None,
                 passlen = 32,
                 quotes = True,
                 backslashes = True,
                 human = False,
                 hashes = None,
                 *args,
                 **kwargs):
        if not chars:
            chars = charsets
        self.charselect = chars
        self.charset = charset
        self.hashnames = hashes
        self.hashes = {}
        self.hasher = None
        self.pw = None
        self.chars = None
        self.case = case
        self.quotes = quotes
        self.passlen = passlen
        self.backslashes = backslashes
        self.human = human
        self.buildCharSet()

    def buildCharSet(self):
        self.chars = self.charselect[self.charset]
        if not self.quotes:
            self.chars = re.sub('["\']', '', self.chars)
        if not self.backslashes:
            self.chars = re.sub('\\\\', '', self.chars)
        if self.human:
            _dupechars = ['`', "'", '|', 'l', 'I', 'i', 'l', '1', 'o', '0', 'O']
            self.chars = ''.join(sorted(list(set(self.chars) - set(_dupechars))))
        if self.case == 'upper':
            self.chars = self.chars.upper()
        elif self.case == 'lower':
            self.chars = self.chars.lower()
        self.chars = ''.join(sorted(list(set(self.chars))))
        return(None)

    def buildHashers(self):
        if self.hashnames:
            if not isinstance(self.hashnames, list):
                _hashes = [self.hashnames]
            for h in self.hashnames:
                if h not in supported_hashes:
                    warnings.warn('Hash algorithm {0} is not a supported hash algorithm'.format(h))
                    continue
                self.hashes[h] = None
            if has_passlib:
                self.hasher = passlib.context.CryptContext(schemes = list(self.hashes.keys()))
            else:
                self.hasher = {}
                for h in self.hashnames:
                    self.hasher[h] = getattr(hashlib, h)
        return(None)

    def generate(self):
        self.genPW()
        self.genHash()
        return(None)

    def genPW(self):
        self.pw = ''
        for _ in range(self.passlen):
            self.pw += random.SystemRandom().choice(self.chars)
        return(None)

    def genHash(self):
        self.buildHashers()
        if not self.hashes or not self.hasher:
            return(None)
        if not self.pw:
            self.genPW()
        for h in self.hashes.keys():
            if has_passlib:
                if h.endswith('_crypt'):
                    try:
                        self.hashes[h] = self.hasher.hash(self.pw, scheme = h, rounds = 5000)
                    except TypeError:
                        self.hashes[h] = self.hasher.hash(self.pw, scheme = h)
                else:
                    self.hashes[h] = self.hasher.hash(self.pw, scheme = h)
            else:
                _hasher = self.hasher[h]
                _hasher.update(self.pw.encode('utf-8'))
                self.hashes[h] = _hasher.hexdigest()
        return(None)


def parseArgs():
    args = argparse.ArgumentParser(description = 'A password generator.')
    args.add_argument('-t', '--type',
                      dest = 'charset',
                      choices = ['simple', 'complex'],  # chars in genPass
                      default = 'complex',
                      help = ('Whether to generate "simple" (no symbols, '
                              'safer for e.g. databases) password(s) or more complex ones. The default is "complex"'))
    args.add_argument('-l', '--length',
                      dest = 'passlen',
                      metavar = 'LENGTH',
                      type = int,
                      default = 32,
                      help = ('The length of the password(s) to generate. The default is 32'))
    args.add_argument('-c', '--count',
                      dest = 'passcount',
                      metavar = 'COUNT',
                      type = int,
                      default = 1,
                      help = ('The number of passwords to generate. The default is 1'))
    args.add_argument('-q', '--no-quotes',
                      dest = 'quotes',
                      action = 'store_false',
                      help = ('If specified, strip out quotation marks (both " and \') from the passwords. '
                              'Only relevant if -t/--type is complex, as simple types don\'t contain these'))
    args.add_argument('-b', '--no-backslashes',
                      dest = 'backslashes',
                      action = 'store_false',
                      help = ('If specified, strip out backslashes. Only relevant if -t/--type is complex, as '
                              'simple types don\'t contain these'))
    args.add_argument('-m', '--human',
                      dest = 'human',
                      action = 'store_true',
                      help = ('If specified, make the passwords easier to read by human eyes (i.e. no 1 and l, '
                              'o or O or 0, etc.)'))
    caseargs = args.add_mutually_exclusive_group()
    caseargs.add_argument('-L', '--lower',
                          dest = 'case',
                          action = 'store_const',
                          const = 'lower',
                          help = 'If specified, make password all lowercase')
    caseargs.add_argument('-U', '--upper',
                          dest = 'case',
                          action = 'store_const',
                          const = 'upper',
                          help = 'If specified, make password all UPPERCASE')
    args.add_argument('-H', '--hash',
                      action = 'append',
                      metavar = 'HASH_NAME',
                      dest = 'hashes',
                      help = ('If specified, also generate hashes for the generated password. '
                              'Pass this argument multiple times for multiple hash types. Use -HL/--hash-list for '
                              'supported hash algorithms'))
    args.add_argument('-HL', '--hash-list',
                      dest = 'only_hashlist',
                      action = 'store_true',
                      help = ('Print the list of supported hash types/algorithms and quit'))
    return(args)


def main():
    args = vars(parseArgs().parse_args())
    if args['only_hashlist']:
        print('SUPPORTED HASH ALGORITHMS:\n')
        print(' *', '\n * '.join(supported_hashes))
        return(None)
    for _ in range(0, args['passcount']):
        p = genPass(**args)
        p.generate()
        print(p.pw)
        if p.hashes:
            print('\nHASHES:')
            for h, val in p.hashes.items():
                print('{0}: {1}'.format(h, val))
            print()
    return(None)


if __name__ == '__main__':
    main()
