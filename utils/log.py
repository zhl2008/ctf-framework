#!/usr/bin/env python
# -*- coding: utf-8 -*-

import color
import sys

class Log():
    @staticmethod
    def _print(word):
        sys.stdout.write(word)
        sys.stdout.flush()
    
    @staticmethod
    def beauty(word):
	res = ''
	beauty_length = 75
	loop = len(word)/beauty_length
	for i in range(loop):
	    res += word[i*beauty_length:i*beauty_length+beauty_length] + "\n    "
	res += word[loop*beauty_length:]
	return res

    @staticmethod
    def info(word):
        Log._print("[+] %s\n" % color.green(word))

    @staticmethod
    def warning(word):
        Log._print("[!] %s\n" % color.yellow(Log.beauty(word)))

    @staticmethod
    def error(word):
        Log._print("[-] %s\n" % color.red(Log.beauty(word)))

    @staticmethod
    def success(word):
        Log._print("[+] %s\n" % color.purple(Log.beauty(word)))

    @staticmethod
    def query(word):
        Log._print("[?] %s\n" % color.underline(Log.beauty(word)))

    @staticmethod
    def context(word):
        Log._print("%s\n" % (color.blue(word)))
