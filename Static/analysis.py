from time import time
import r2pipe
import json
import pefile
import re
import pyimpfuzzy

import docx
import hashlib
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
from Static import Static_Extraction


class Static: 
    def __init__(self, url): 
        self.url = url
        self.r2p = r2pipe.open(self.url)
        self.r2p.cmd("e bin.hashlimit=10000M")

    def hash_256(self):
        BLOCK_SIZE = 65536 # The size of each read from the file

        file_hash = hashlib.sha256() 
        with open(self.url, 'rb') as f: 
            fb = f.read(BLOCK_SIZE) 
            while len(fb) > 0: 
                file_hash.update(fb) 
                fb = f.read(BLOCK_SIZE) 
        hash256 = file_hash.hexdigest()
        return hash256

    def get_all_calls(self):
        print("retrieving ALL calls from the malware "+self.url)
        functions = self.r2p.cmd("aa;aflj")
        funcs = json.loads(functions)
        return funcs

    def get_api_calls(self):
        print("retrieving API calls from the malware "+self.url)
        apis = self.r2p.cmd("aa;aaa;axtj @@ sym.*")
        apilines = apis.split('\n')
        data = []
        first = 0
        for line in apilines:
            if line[1:-1] != '':
                if first == 0:
                    first = 1

                    data = data + line[1:-1] 
                else:
                    data = data  + ','+ line[1:-1] 

        data = "[" + data + "]"
        apicalls = json.loads(data)
        return apicalls

    def get_headers(self):
        print("retrieving headers from the malware "+self.url)
        headers = self.r2p.cmd("aa;ij")
        headers = json.loads(headers)
        return headers

    def get_libraries(self):
        print("retrieving libraries from the malware "+self.url)
        libs = self.r2p.cmd("aa;ilj")
        return libs

    def get_network_ops(self):
        print("retrieving network ops from the malware "+self.url)

        sa = Static_Extraction.StaticAnalysis(self.url)
        ipv4s = sa.get_ipv4_addresses()
        ipv6s = sa.get_ipv6_addresses()
        domains = sa.get_domains()
        urls = sa.get_urls()
        #network = r2p.cmd("aa;izz")
        #urls = re.findall("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", network)
        network = ipv4s + ipv6s + domains + urls
        #network = r2p.cmd("aa;izz")
        #ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", network)
        #urls = re.findall("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", network)
        #network = ips + urls
        return network

    def get_strings(self):
        print("retrieving strings from the malware "+self.url)
        strings = self.r2p.cmd("aaa;izj")
        return strings

    def get_entropy(self): 
        try: 
            binary = pefile.PE(self.url)
            entropy_dict = []
            for section in binary.sections:
                entropy_dict.append([str(section.Name).replace('\\x00', '').replace('b\'',''), hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData, section.get_entropy() ])
        except pefile.PEFormatError: 
            entropy_dict = 'No PE DOS Header found' 
        return entropy_dict

    def get_imphash(self): 
        try: 
            file=pefile.PE(self.url)
            imphash = file.get_imphash()
        except pefile.PEFormatError: 
            print('Warning: No PE DOS Header found for the selected file')
            imphash = 'No PE DOS Header found' 

        return imphash

    def get_impfuzzy(self): 
        try: 
            hsh = pyimpfuzzy.get_impfuzzy(self.url)
        except pefile.PEFormatError: 
            hsh = 'No PE DOS Header found' 
        return hsh

    def macrodetect(self):
        mc=open(self.url, 'rb')
        mcparce=VBA_Parser(mc)
        if mcparce.detect_vba_macros():
            print ("VBA Macros found")
            return 1
        else:
            print ("No VBA Macros found")
            return 0
            
    def mine_pdf(self):
        fp = open(self.url, 'rb')
        parser = PDFParser(fp)
        doc = PDFDocument(parser)
        return doc.info  # The "Info" metadata

    def mine_doc(self):
        metadata = {}
        doc = docx.Document(self.url)
        prop = doc.core_properties
        metadata["author"] = prop.author
        metadata["category"] = prop.category
        metadata["comments"] = prop.comments
        metadata["content_status"] = prop.content_status
        metadata["created"] = prop.created
        metadata["identifier"] = prop.identifier
        metadata["keywords"] = prop.keywords
        metadata["language"] = prop.language
        metadata["modified"] = prop.modified
        metadata["subject"] = prop.subject
        metadata["title"] = prop.title
        metadata["version"] = prop.version
        return metadata