#!/usr/bin/env python3

import vaultpass


def main():
    rawargs = vaultpass.args.parseArgs()
    args = rawargs.parse_args()
    if not args.oper:
        rawargs.print_help()
        return(None)
    if args.oper == 'help':
        rawargs.print_help()
        return(None)
    if args.oper == 'version':
        print('{0} {1}'.format(vaultpass.constants.NAME,
                               vaultpass.constants.VERSION))
    args.initialize = (True if args.oper == 'init' else False)
    args.verify_cfg = (True if args.oper == 'verify' else False)
    vp = vaultpass.VaultPass(**vars(args))
    return(None)


if __name__ == '__main__':
    main()
