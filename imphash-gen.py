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
import shelve
from hashlib import md5

def getFiles(dir, recursive):
	# Recursive
	if recursive:
		for root, directories, files in os.walk (dir, followlinks=False):
			for filename in files:
				filePath = os.path.join(root,filename)
				yield filePath
	# Non recursive
	else:
		for filename in os.listdir(dir):
			filePath = os.path.join(dir,filename)
			yield filePath		

def createGoodImps(dir, recursive=False):
	imps = []
	for filePath in getFiles(dir, recursive):
		# print filePath
		try:
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
			
def parseDir(dir, goodimps, recursive ):
	
	imps = {}
	implist = []
	
	for filePath in getFiles(dir, recursive):
		# print filePath
		try:
			p = pefile.PE(filePath)
			imphash = p.get_imphash()
			
			print "IMP: %s MD5: %s FILE: %s" % ( imphash, getMd5(filePath), filePath )
			
			if imphash in goodimps:
				print "GOOD IMPS - do not use -------------------------------------------"
			
			# If already known
			if imphash in implist:
				# Check for imphash in list
				for file in imps:
					# print imps[file]," ",imphash
					if imps[file] == imphash:
						md5 = getMd5(file)
						print "   MATCH with MD5: %s FILE: %s" % ( md5, file )
			else:			
				# Add to list
				# print "add"
				implist.append(imphash)
				# print implist
				
			imps[filePath] = imphash
			
		except Exception, e:
			# traceback.print_exc()
			pass
	
	
def isAscii(b):
	if ord(b)<127 and ord(b)>31 :
		return 1 
	return 0

def printWelcome():
	print "###############################################################################"
	print " "
	print "  IMPHASH Generator"
	print "  by Florian Roth"
	print "  January 2014"
	print "  Version 0.6.1"
	print " "
	print "###############################################################################"                               

# MAIN ################################################################
if __name__ == '__main__':
	
	# Parse Arguments
	parser = argparse.ArgumentParser(description='ImpHash Generator')
	parser.add_argument('-p', help='Path to scan', metavar='path-to-scan', required=True)
	parser.add_argument('-d', help='Imphash Database File (default: goodimps.db)', metavar='dbfile', default="goodimps.db")
	parser.add_argument('-r', action='store_true', default=False, help='recursive scan')	
	parser.add_argument('--createdb', action='store_true', default=False, help='Create good imphashes database')
	parser.add_argument('--updatedb', action='store_true', default=False, help='Update good imphashes database')
	parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
	
	args = parser.parse_args()
	
	# Print Welcome
	printWelcome()
	
	# Create DB with good imphashes
	if args.createdb and args.p:
		imps = createGoodImps(args.p, args.r)
		
		goodimps_shelve = shelve.open(args.d)
		goodimps_shelve["imps"] = imps
		print "New DB item count: %s" % str(len(imps))
		goodimps_shelve.sync()
		goodimps_shelve.close()

	# Update DB with good imphashes
	if args.updatedb and args.p:
		imps = createGoodImps(args.p, args.r)
		
		goodimps_shelve = shelve.open(args.d)
		old_imps = goodimps_shelve["imps"]
		print "Old DB item count: %s" % str(len(old_imps))
		
		new_imps = old_imps + imps
		
		goodimps_shelve["imps"] = new_imps
		print "New DB item count: %s" % str(len(new_imps))
		
		goodimps_shelve.sync()
		goodimps_shelve.close()
		
	# Create useful Import hashes
	else:	
		# Read Good Imps
		goodimps_shelve = shelve.open(args.d)
		goodimps = goodimps_shelve["imps"]
		
		print "Reading DB: %s imphashes found" % str(len(goodimps))

		# Parse Directory
		parseDir(args.p, goodimps, args.r)
	