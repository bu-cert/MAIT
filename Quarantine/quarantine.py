from Crypto.Cipher import AES
import hashlib
import pefile
import zipfile
import pe
import random
import os, random, struct


def encrypt_file( key, in_filename, out_filename=None, chunksize=64*1024):
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = 'This is an IV456'.encode("utf8")
    
    encryptor = AES.new(key, AES.MODE_CBC, iv )
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += bytes(' ' * (16 - len(chunk) % 16), encoding='ascii')

                outfile.write(encryptor.encrypt(chunk))

def adjust_SectionSize(sz, align):
    if sz % align: sz = ((sz + align) // align) * align
    return sz

def inject_new_section(url, sha256name):
    pe = pefile.PE(url)
    last_section = pe.sections[-1]
    new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
    # fill with zeros
    new_section.__unpack__(bytearray(new_section.sizeof()))
    # place section header after last section header (assume there is enough room)
    new_section.set_file_offset(last_section.get_file_offset() + last_section.sizeof())
    new_section.Name = b'.notgonnarun'
    new_section_size = 100
    new_section.SizeOfRawData = adjust_SectionSize(new_section_size, pe.OPTIONAL_HEADER.FileAlignment)
    new_section.PointerToRawData = len(pe.__data__)
    new_section.Misc = new_section.Misc_PhysicalAddress = new_section.Misc_VirtualSize = new_section_size
    new_section.VirtualAddress = last_section.VirtualAddress + adjust_SectionSize(last_section.Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment)
    new_section.Characteristics = 0x40000000 

    # change address of entry point to beginning of new section
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_section.VirtualAddress
    # increase size of image
    pe.OPTIONAL_HEADER.SizeOfImage += adjust_SectionSize(new_section_size, pe.OPTIONAL_HEADER.SectionAlignment)
    # increase number of sections
    pe.FILE_HEADER.NumberOfSections += 1
    # append new section to structures
    pe.sections.append(new_section)
    pe.__structures__.append(new_section)
    pe.write('./Disposal/'+sha256name+'.quarantine')
    pe.close()
