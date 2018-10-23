#!/usr/bin/python
#
# Script to generate hashed export function rainbow table.
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

__description__ = 'Export Rainbow Table Generator'
__author__ = 'Christian Giuffre'
__version__ = '0.1.0'
__date__ = '20181023'

import fileformat.pe
import os.path
import sqlite3

DLL_DIRECTORY = "./dlls"
DLL_FILENAME = "kernel32.dll"

DB_DIRECTORY = "./db/"
DB_FILENAME = "exportname_rainbowtable.db"

def createConnection(dbFile):
    try:
        conn = sqlite3.connect(dbFile)
        return conn
    except sqlite3.Error as e:
        print(e)
 
    return None

def executeCommand(conn, commandString):
    try:
        c = conn.cursor()
        c.execute(commandString)
    except sqlite3.Error as e:
        print(e)

def hash(filename, exportname):
    # first converts the filename to uppercase null terminated unicoded
    filename = map(lambda x: ord(x), filename.upper())
    filename.append(0)

    for x in range(len(filename)):
        filename.insert(x*2+1, 0)

    # next convert the exportname to a null terminated string
    exportname = map(lambda x: ord(x), exportname)
    exportname.append(0)

    bit_mask = 0xffffffff
    bit_width = 32

    # hash the filename
    filename_hash = 0
    for x in filename:
        filename_hash = ((filename_hash << (bit_width - 0xd)) & bit_mask) | filename_hash >> 0xd
        filename_hash = (filename_hash + x) & bit_mask

    # hash the exportname
    exportname_hash = 0
    for x in exportname:
        exportname_hash = ((exportname_hash << (bit_width - 0xd)) & bit_mask) | exportname_hash >> 0xd
        exportname_hash = (exportname_hash + x) & bit_mask

    # generate the final hash
    return ((filename_hash + exportname_hash) & bit_mask)

def main():
    DLL_PATH = os.path.join(DLL_DIRECTORY, DLL_FILENAME)

    with open(DLL_PATH, 'rb') as fp:
        export_names = fileformat.pe.extract(fp)

    createRainbowTable = ''' CREATE TABLE IF NOT EXISTS rainbow (
                                      hash TEXT PRIMARY KEY NOT NULL,
                                      functionname TEXT NOT NULL
                               );'''
    
    DB_PATH = os.path.join(DB_DIRECTORY, DB_FILENAME)

    conn = createConnection(DB_PATH)

    if conn is None:
        print("[!] Error: Unable to establish connection to the database.")
    else:
        executeCommand(conn, createRainbowTable)
        conn.commit()

    for x in export_names.keys():
        for y in export_names[x]:
            executeCommand(conn, "INSERT INTO rainbow VALUES ('{0}','{1}.{2}')".format(hex(hash(x, y)), x, y))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    main()