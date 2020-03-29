#!/usr/bin/env python3

import vaultpass

cfg = vaultpass.config.LocalFile('/tmp/vaultpass.xml')
cfg.main()

