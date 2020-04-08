import os
import string

# These are static.
NAME = 'VaultPass'
VERSION = '0.0.1'
SUPPORTED_ENGINES = ('kv1', 'kv2', 'cubbyhole')
SUPPORTED_OUTPUT_FORMATS = ('pretty', 'yaml', 'json')
ALPHA_LOWER_PASS_CHARS = string.ascii_lowercase
ALPHA_UPPER_PASS_CHARS = string.ascii_uppercase
ALPHA_PASS_CHARS = ALPHA_LOWER_PASS_CHARS + ALPHA_UPPER_PASS_CHARS
NUM_PASS_CHARS = string.digits
ALPHANUM_PASS_CHARS = ALPHA_PASS_CHARS + NUM_PASS_CHARS
SYMBOL_PASS_CHARS = string.punctuation
ALL_PASS_CHARS = ALPHANUM_PASS_CHARS + SYMBOL_PASS_CHARS
SHOW_CLIP_LINENUM = 1
# These CAN be generated dynamically, see below.
CLIP_TIMEOUT = 45
SELECTED_PASS_CHARS = ALL_PASS_CHARS
SELECTED_PASS_NOSYMBOL_CHARS = ALPHANUM_PASS_CHARS
# xclip(1)
ALLOWED_CLIPBOARDS = ('primary', 'secondary', 'clipboard')
CLIPBOARD = 'clipboard'
GENERATED_LENGTH = 25  # I personally would prefer 32, but Pass compatibility...
EDITOR = 'vi'  # vi is on ...every? single distro and UNIX/UNIX-like, to my knowledge.
GPG_HOMEDIR = '~/.gnupg'
SELECTED_GPG_HOMEDIR = GPG_HOMEDIR
PASS_DIR = '~/.password-store'

if not os.environ.get('NO_VAULTPASS_ENVS'):
    # These are dynamically generated from the environment.
    CLIP_TIMEOUT = int(os.environ.get('PASSWORD_STORE_CLIP_TIME', CLIP_TIMEOUT))
    SELECTED_PASS_CHARS = os.environ.get('PASSWORD_STORE_CHARACTER_SET', SELECTED_PASS_CHARS)
    SELECTED_PASS_NOSYMBOL_CHARS = os.environ.get('PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS',
                                                  SELECTED_PASS_NOSYMBOL_CHARS)
    CLIPBOARD = os.environ.get('PASSWORD_STORE_X_SELECTION', CLIPBOARD)
    GENERATED_LENGTH = int(os.environ.get('PASSWORD_STORE_GENERATED_LENGTH', GENERATED_LENGTH))
    EDITOR = os.environ.get('EDITOR', EDITOR)
    SELECTED_GPG_HOMEDIR = os.environ.get('GNUPGHOME', GPG_HOMEDIR)
    PASS_DIR = os.environ.get('PASSWORD_STORE_DIR', PASS_DIR)

# These are made more sane.
PASS_DIR = os.path.abspath(os.path.expanduser(PASS_DIR))
SELECTED_GPG_HOMEDIR = os.path.abspath(os.path.expanduser(SELECTED_GPG_HOMEDIR))
