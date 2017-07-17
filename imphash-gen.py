#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# ImpHash Generator
# A Simple PE Import Hash Generator
#
# Florian Roth
# February 2014
# v0.1

import os
import sys
import argparse
import traceback
import pefile
import pickle
import gzip
from collections import Counter
from hashlib import md5

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

def getFiles(dir, recursive):
    # Recursive
    if recursive:
        for root, directories, files in os.walk(dir, followlinks=False):
            for filename in files:
                filePath = os.path.join(root, filename)
                yield filePath
    # Non recursive
    else:
        for filename in os.listdir(dir):
            filePath = os.path.join(dir, filename)
            yield filePath


def createGoodImps(dir, recursive=False):
    imps = []
    for filePath in getFiles(dir, recursive):
        # print filePath
        try:
            if args.debug:
                print "Processing %s ..." % filePath
            p = pefile.PE(filePath)
            imphash = p.get_imphash()

            imps.append(imphash)
            sys.stdout.write(".")

        except Exception, e:
            # traceback.print_exc()
            pass

    return imps


def getMd5(filePath):
    md5sum = "-"
    try:
        f = open(filePath, 'rb')
        filedata = f.read()
        f.close()
        # Generate md5
        md5sum = md5(filedata).hexdigest()
        return md5sum
    except Exception, e:
        print traceback.print_exc()
        return "-"
        pass
    return md5sum


def parseDir(dir, goodimps, recursive):
    imps = {}
    implist = []

    for filePath in getFiles(dir, recursive):
        # print filePath
        try:
            p = pefile.PE(filePath)
            imphash = p.get_imphash()

            print "%s  %s" % (imphash, filePath)

            if imphash in goodimps:
                print "GOOD IMPS - do not use -------------------------------------------"

            # If already known
            if imphash in implist:
                # Check for imphash in list
                for file in imps:
                    # print imps[file]," ",imphash
                    if imps[file] == imphash:
                        print "   MATCH with FILE: %s" % (md5, file)
            else:
                # Add to list
                # print "add"
                implist.append(imphash)
            # print implist

            imps[imphash].append(file)

        except Exception, e:
            # traceback.print_exc()
            pass


def save(object, filename, protocol=0):
    file = gzip.GzipFile(filename, 'wb')
    file.write(pickle.dumps(object, protocol))
    file.close()


def load(filename):
    file = gzip.GzipFile(filename, 'rb')
    buffer = ""
    while 1:
        data = file.read()
        if data == "":
            break
        buffer += data
    object = pickle.loads(buffer)
    del (buffer)
    file.close()
    return object


def isAscii(b):
    if ord(b) < 127 and ord(b) > 31:
        return 1
    return 0


def get_abs_path(filename):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


def printWelcome():
    print "###############################################################################"
    print " "
    print "  IMPHASH Generator"
    print "  by Florian Roth"
    print "  July 2017"
    print "  Version 0.7.0"
    print " "
    print "###############################################################################"


# MAIN ################################################################
if __name__ == '__main__':

    # Parse Arguments
    parser = argparse.ArgumentParser(description='ImpHash Generator')
    parser.add_argument('-p', help='Path to scan', metavar='path-to-scan', required=True)
    parser.add_argument('-d', help='Imphash Database File (default: goodimps.db)', metavar='dbfile',
                        default="goodimps.db")
    parser.add_argument('-r', action='store_true', default=False, help='recursive scan')
    parser.add_argument('--createdb', action='store_true', default=False, help='Create good imphashes database')
    parser.add_argument('--updatedb', action='store_true', default=False, help='Update good imphashes database')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    # Print Welcome
    printWelcome()

    # Create DB with good imphashes
    if args.createdb and args.p:
        print "Checking %s" % args.p
        imps = createGoodImps(args.p, args.r)
        print "New DB item count: %s" % str(len(imps))
        save(imps, args.d)

    # Update DB with good imphashes
    if args.updatedb and args.p:
        good_imps_db = Counter()
        good_imps = load(get_abs_path(args.d))
        good_imps_db.update(good_imps)

        print "Old DB item count: %s" % str(len(good_imps))

        new_imps = createGoodImps(args.p, args.r)
        new_imps = good_imps + new_imps

        save(new_imps, args.d)
        print "New DB item count: %s" % str(len(new_imps))

    # Create useful Import hashes
    else:
        # Read Good Imps
        good_imps_db = Counter()
        good_imps = load(get_abs_path(args.d))
        good_imps_db.update(good_imps)

        print "Reading DB: %s imphashes found" % str(len(good_imps))

        # Parse Directory
        parseDir(args.p, good_imps, args.r)
