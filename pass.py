#!/usr/bin/env python3

import vaultpass


def main():
    rawargs = vaultpass.args.parseArgs()
    args = rawargs.parse_args()
    if not args.oper:
        args.oper = 'show'
    import pprint
    pprint.pprint(vars(args))
    return(None)


if __name__ == '__main__':
    main()
