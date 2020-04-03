#!/bin/bash

asciidoctor README.adoc -o ./README.html
asciidoctor -b manpage -o - vaultpass.1.adoc | gzip -c -9 > vaultpass.1.gz
