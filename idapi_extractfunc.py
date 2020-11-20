#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from idautils import *
from idc import *
from idaapi import *

# PE Entry Point
start_add = BeginEA()
# Check the function of the binary
for func in Functions(SegStart(start_add), SegEnd(start_add)):
	func_name = GetFunctionName(func)
	func_start = func
	# Print address and function nam
	print("%08x " % func_start)
	print("%s\n" %str(func_name))
