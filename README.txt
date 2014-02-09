#
# IMPHash Generator
# by Florian Roth
# February 2014
#

This tool generates "PE import hashes" for all executables it finds in the given
directory and marks every import hash as unusable that can also be found in the
goodware-hash-database.

The goodware hash database contains hash values from:
- Windows 7 64bit system folder
- Cygwin 32 bit
- Office 2012
- Python 2.7

Typical use cases:
================================================================================

Scan a directory and generate the PE import hashes for all executables in this 
directory 

    python imphash-gen.py -p X:\MAL\Virus1

Generate a goodware hash database from my Windows directory:

    python imphash-gen.py --createdb -r -p C:\Windows

Update the goodware hash database with PE import hashes generated from 
executables from the programs folder.

    python imphash-gen.py --updatedb -r -p "C:\Program Files"