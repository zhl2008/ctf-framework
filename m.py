#!/usr/bin/env python

'''
This script is designed to do quick maintaince in AWD game, 
on account that haozigege is lazy

'''

from framework import config
from maintain import function


def banner():
	my_banner = ""
	my_banner += "                   _                     _       _        _       \n"
	my_banner += "  __ ___      ____| |    _ __ ___   __ _(_)_ __ | |_ __ _(_)_ __  \n"
	my_banner += " / _` \ \ /\ / / _` |   | '_ ` _ \ / _` | | '_ \| __/ _` | | '_ \ \n"
	my_banner += "| (_| |\ V  V / (_| |   | | | | | | (_| | | | | | || (_| | | | | |\n"
	my_banner += " \__,_| \_/\_/ \__,_|___|_| |_| |_|\__,_|_|_| |_|\__\__,_|_|_| |_|\n"
	my_banner += "                   |_____|                                        \n"
	my_banner += "                                                    Hence@Lancet  \n"
	my_banner += "\n"

	print my_banner


def parse_options():

	parser = OptionParser()
	parser.add_option("-m", "--module",\
					 dest="module", default="sample",\
					  help="Input the module here :)")
	
	parser.add_option("-c", "--command",\
					 dest="command", default="get_flag",\
					  help="The command you want to run")
	
	parser.add_option("-r", "--random_ua",\
					 dest="random_ua", default="False",\
					  help="Enable the random UA to avoid filter")
	parser.add_option("-l", "--loop",\
					 dest="loop_count", default="65535",\
					  help="To set the loop count for this program")
	parser.add_option("-t", "--udf_target",\
					 dest="udf_target", default="",\
					  help="To set the target for attacking, split with ,")
	parser.add_option("-x", "--thread",\
					 dest="thread", default="1",\
					  help="To set thread number for attacking")
	(options, args) = parser.parse_args()

	return options

if __name__ == "__main__":
	banner()