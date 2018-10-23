#!/usr/bin/python
#
# Script to resolve hashed function names in shellcode.
#
# Copyright 2018, Christian Giuffre <christian@int3rrupt.com>.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

__description__ = "IDA Python Resolve Hash Function Names Script"
__author__ = "Christian Giuffre"
__version__ = "0.1.0"
__date__ = "20181023"

import os.path
import sqlite3

DB_DIRECTORY = "./"
DB_FILENAME = "exportname_rainbowtable.db"

def lookuphash(hashvalue):
    DB_PATH = os.path.abspath(os.path.join(DB_DIRECTORY, DB_FILENAME))
    print DB_PATH

    connection = sqlite3.connect(DB_PATH)

    if connection is None:
        print("[!] Error: Unable to establish connection to the database.")
    else:
        cursor = connection.cursor()
        cursor.execute("""
                        SELECT functionname
                        FROM rainbow
                        WHERE hash="{0}";
                        """.format(hashvalue))
        
        result = cursor.fetchone()

        functionname = "Unknown Function Name"

        if result is not None:
         (functionname,) = result

        connection.close()

        return str(functionname)

def main():
    for seg_start in Segments():
        addrs =  list(Heads(seg_start, SegEnd(seg_start)))

        for index in range(len(addrs)):
            addr = addrs[index]
            if isCode(GetFlags(addr)) and GetMnem(addr) == "call" and GetOpnd(addr,0) ==  "ebp":
                MakeComm(addr, lookuphash(str(hex(int(GetOperandValue(addrs[index-1], 0) & 0xffffffff)))))


if __name__ == "__main__":
    main()