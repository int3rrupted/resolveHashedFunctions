#!/usr/bin/python
#
# Script to statically extract function name exports from a portable executable.
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

__description__ = "Static Portable Executable Export Extractor"
__author__ = "Christian Giuffre"
__version__ = "0.1.0"
__date__ = "20181023"

from ctypes import *
from datetime import *

EPOC = datetime(1970, 1, 1)

IMAGE_DOS_SIGNATURE = 0x5A4D      # MZ
IMAGE_NT_SIGNATURE = 0x00004550   # PE00

IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

IMAGE_DIRECTORY_ENTRY_EXPORT = 0            # Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT = 1            # Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2          # Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3         # Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY = 4          # Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5         # Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG = 6             # Debug Directory
IMAGE_DIRECTORY_ENTRY_COPYRIGHT = 7         # (X86 usage)
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7      # Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8         # RVA of GP
IMAGE_DIRECTORY_ENTRY_TLS = 9               # TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10      # Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11     # Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT = 12              # Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13     # Delay Load Import Descriptors
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14   # COM Runtime descriptor

IMAGE_SIZEOF_SHORT_NAME = 8

class IMAGE_DOS_HEADER(Structure):
    _fields_ = [('e_magic', c_ushort),         # Magic number
                ('e_cp', c_ushort),            # Pages in file
                ('e_crlc', c_ushort),          # Relocations
                ('e_cparhdr', c_ushort),       # Size of header in paragraphs
                ('e_minalloc', c_ushort),      # Minimum extra paragraphs needed
                ('e_maxalloc', c_ushort),      # Maximum extra paragraphs needed
                ('e_ss', c_ushort),            # Initial (relative) SS value
                ('e_sp', c_ushort),            # Initial SP value
                ('e_csum', c_ushort),          # Checksum
                ('e_ip', c_ushort),            # Initial IP value
                ('e_cs', c_ushort),            # Initial (relative) CS value
                ('e_lfarlc', c_ushort),        # File address of relocation table
                ('e_ovno', c_ushort),          # Overlay number
                ('e_res', c_ushort * 4),       # Reserved words
                ('e_oemid', c_ushort),         # OEM identifier (for e_oeminfo)
                ('e_oeminfo', c_ushort),       # OEM information; e_oemid specific
                ('e_res2', c_ushort * 10),     # Reserved words
                ('e_lfanew', c_int)]           # File address of new exe header

    def __repr__(self):
        raise NotImplementedError()

class IMAGE_FILE_HEADER(Structure):
    _fields_ = [('Machine', c_ushort),
                ('NumberOfSections', c_ushort),
                ('TimeDateStamp', c_uint),
                ('PointerToSymbolTable', c_uint),
                ('NumberOfSymbols', c_uint),
                ('SizeOfOptionalHeader', c_ushort),
                ('Characteristics', c_ushort)]

    def __repr__(self):
        raise NotImplementedError()

class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [('VirtualAddress', c_uint),
                ('Size', c_uint)]

    def __repr__(self):
        raise NotImplementedError()

class IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ = [('Magic', c_ushort),
                ('MajorLinkerVersion', c_ubyte),
                ('MinorLinkerVersion', c_ubyte),
                ('SizeOfCode', c_uint),
                ('SizeOfInitializedData', c_uint),
                ('SizeOfUninitializedData', c_uint),
                ('AddressOfEntryPoint', c_uint),
                ('BaseOfCode', c_uint),
                ('BaseOfData', c_uint),
                ('ImageBase', c_uint),
                ('SectionAlignment', c_uint),
                ('FileAlignment', c_uint),
                ('MajorOperatingSystemVersion', c_ushort),
                ('MinorOperatingSystemVersion', c_ushort),
                ('MajorImageVersion', c_ushort),
                ('MinorImageVersion', c_ushort),
                ('MajorSubsystemVersion', c_ushort),
                ('MinorSubsystemVersion', c_ushort),
                ('Win32VersionValue', c_uint),
                ('SizeOfImage', c_uint),
                ('SizeOfHeaders', c_uint),
                ('CheckSum', c_uint),
                ('Subsystem', c_ushort),
                ('DllCharacteristics', c_ushort),
                ('SizeOfStackReserve', c_uint),
                ('SizeOfStackCommit', c_uint),
                ('SizeOfHeapReserve', c_uint),
                ('SizeOfHeapCommit', c_uint),
                ('LoaderFlags', c_uint),
                ('NumberOfRvaAndSizes', c_uint),
                ('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)]

    def __repr__(self):
        raise NotImplementedError()

class IMAGE_OPTIONAL_HEADER64(Structure):
    _fields_ = [('Magic', c_ushort),
                ('MajorLinkerVersion', c_ubyte),
                ('MinorLinkerVersion', c_ubyte),
                ('SizeOfCode', c_uint),
                ('SizeOfInitializedData', c_uint),
                ('SizeOfUninitializedData', c_uint),
                ('AddressOfEntryPoint', c_uint),
                ('BaseOfCode', c_uint),
                ('ImageBase', c_ulonglong),
                ('SectionAlignment', c_uint),
                ('FileAlignment', c_uint),
                ('MajorOperatingSystemVersion', c_ushort),
                ('MinorOperatingSystemVersion', c_ushort),
                ('MajorImageVersion', c_ushort),
                ('MinorImageVersion', c_ushort),
                ('MajorSubsystemVersion', c_ushort),
                ('MinorSubsystemVersion', c_ushort),
                ('Win32VersionValue', c_uint),
                ('SizeOfImage', c_uint),
                ('SizeOfHeaders', c_uint),
                ('CheckSum', c_uint),
                ('Subsystem', c_ushort),
                ('DllCharacteristics', c_ushort),
                ('SizeOfStackReserve', c_ulonglong),
                ('SizeOfStackCommit', c_ulonglong),
                ('SizeOfHeapReserve', c_ulonglong),
                ('SizeOfHeapCommit', c_ulonglong),
                ('LoaderFlags', c_uint),
                ('NumberOfRvaAndSizes', c_uint),
                ('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)]

    def __repr__(self):
        raise NotImplementedError()

class IMAGE_SECTION_HEADER(Structure):
    _fields_ = [('Name', c_char * IMAGE_SIZEOF_SHORT_NAME),
                ('VirtualSize', c_uint),
                ('VirtualAddress', c_uint),
                ('SizeOfRawData', c_uint),
                ('PointerToRawData', c_uint),
                ('PointerToRelocations', c_uint),
                ('PointerToLinenumbers', c_uint),
                ('NumberOfRelocations', c_ushort),
                ('NumberOfLinenumbers', c_ushort),
                ('Characteristics', c_uint)]

    def __repr__(self):
        raise NotImplementedError()

class IMAGE_EXPORT_DIRECTORY(Structure):
    _fields_ = [('Characteristics', c_uint),
                ('TimeDateStamp', c_uint),
                ('MajorVersion', c_ushort),
                ('MinorVersion', c_ushort),
                ('Name', c_uint),
                ('Base', c_uint),
                ('NumberOfFunctions', c_uint),
                ('NumberOfNames', c_uint),
                ('AddressOfFunctions', c_uint),
                ('AddressOfNames', c_uint),
                ('AddressOfNameOrdinals', c_uint)]

    def __repr__(self):
        raise NotImplementedError()        

def rvatoraw(section_table, rva):
    for entry in section_table:
        if (rva >= entry.VirtualAddress) and (rva <= (entry.VirtualAddress + entry.VirtualSize)):
            return (rva - entry.VirtualAddress + entry.PointerToRawData)

    raise RuntimeError("Error: Supplied Relative Virtual Address not within supplied Section Table ranges")

def read_c_string(fp, position, max_length=256):
    saved_address = fp.tell()

    fp.seek(position, 0)

    c_string = ''
    for counter in range(max_length):
        char = fp.read(1)
        if (ord(char) == 0):
            break
        c_string += char

    fp.seek(saved_address, 0)

    return c_string


def extract(fp):
    try:   
        image_dos_header = IMAGE_DOS_HEADER();
        fp.readinto(image_dos_header)

        if (image_dos_header.e_magic != IMAGE_DOS_SIGNATURE):
            raise RuntimeError("Error: File doesn't contain valid DOS Signature")

        fp.seek(image_dos_header.e_lfanew, 0)

        pe_signature = c_uint()
        fp.readinto(pe_signature)

        if (pe_signature.value != IMAGE_NT_SIGNATURE):
            raise RuntimeError("Error: File doesn't contain valid Portable Executable Signature")

        image_file_header = IMAGE_FILE_HEADER()
        fp.readinto(image_file_header)

        if (image_file_header.SizeOfOptionalHeader == 0x00):
            raise RuntimeError("Error: File contains a zero length Optional Header")

        optional_magic_header = c_ushort();
        fp.readinto(optional_magic_header);

        if (optional_magic_header.value not in [IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC]):
            raise RuntimeError("Error: File contains an invalid or unsupported Option Header magic value")

        fp.seek(sizeof(optional_magic_header) * -1, 1)

        if (optional_magic_header.value == IMAGE_NT_OPTIONAL_HDR32_MAGIC):
            image_optional_header = IMAGE_OPTIONAL_HEADER()
        else:
            image_optional_header = IMAGE_OPTIONAL_HEADER64()

        fp.readinto(image_optional_header)

        section_table = (IMAGE_SECTION_HEADER * image_file_header.NumberOfSections)()
        fp.readinto(section_table)
        
        export_directory_raw_address = rvatoraw(section_table, image_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
        export_directory_table = IMAGE_EXPORT_DIRECTORY()
        fp.seek(export_directory_raw_address, 0)
        fp.readinto(export_directory_table)

        name = read_c_string(fp, rvatoraw(section_table, export_directory_table.Name))
        number_of_functions = export_directory_table.NumberOfNames
        raw_AddressOfNames = (rvatoraw(section_table, export_directory_table.AddressOfNames))

        fp.seek(raw_AddressOfNames, 0)

        export_names = []
        entry = c_uint()
        for x in range(number_of_functions):
            fp.readinto(entry)
            export_names.append(read_c_string(fp, rvatoraw(section_table,entry.value)))

        
        return {name: export_names}
            

    except OSError as e:
        print e

    except RuntimeError as e:
        print e