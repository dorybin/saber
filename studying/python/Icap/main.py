#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
主函数执行部分
'''

import sys,os

#path=os.path.dirname(__file__)
#path+="\gui"
#sys.path.append(path) 
##print(sys.path)

#import frame 
from frame import ex #引用模块中的函数 

if __name__=="__main__":
    ex.MainLoop() 