#!/usr/bin/python3
#Copyright 2016, William Stearns <william.l.stearns@gmail.com>
#Released under the GPL
#V0.11

import fileinput			#Allows one to read from files specified on the command line or read directly from stdin automatically
import sys				#Direct access to filehandles


AlreadySeen = set()			#Set of lines/strings we've already seen

SilentFilenames = [ ]			#Filenames supplied following a "-s"; lines in these will be loaded but never printed.  They suppress printing
					#of lines that show up in the Normal files.
NormalFilenames = [ ]



ParamPointer = 1
while (ParamPointer < len(sys.argv)):
	if (sys.argv[ParamPointer] == "-h"):
		Usage()
	elif (sys.argv[ParamPointer] == "-s"):
		if (ParamPointer + 1 >= len(sys.argv)):
			Debug("'-s' command line option requested, but no SilentFilename following it, exiting.")
			Usage()
		else:
			SilentFilenames.append(sys.argv[ParamPointer + 1])
			ParamPointer += 1
	else:
		NormalFilenames.append(sys.argv[ParamPointer])
	ParamPointer += 1


if len(SilentFilenames) > 0:
	for OneLine in fileinput.input(SilentFilenames):
		if OneLine not in AlreadySeen:
			AlreadySeen.add(OneLine)

for OneLine in fileinput.input(NormalFilenames):
	if OneLine not in AlreadySeen:
		sys.stdout.write(OneLine)
		AlreadySeen.add(OneLine)
	#To send duplicate lines to stderr, do this:
	#else:
	#	sys.stderr.write(OneLine)

