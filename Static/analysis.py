
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
    def hash_256(self, url):
        BLOCK_SIZE = 65536 # The size of each read from the file

        file_hash = hashlib.sha256() 
        with open(url, 'rb') as f: 
            fb = f.read(BLOCK_SIZE) 
            while len(fb) > 0: 
                file_hash.update(fb) 
                fb = f.read(BLOCK_SIZE) 
        hash256 = file_hash.hexdigest()
        return hash256



    def macrodetect(self, url):
        mc=open(url, 'rb')
        mcparce=VBA_Parser(mc)
        if mcparce.detect_vba_macros():
            print ("VBA Macros found")
            return 1
        else:
            print ("No VBA Macros found")
            return 0
            
    def mine_pdf(self,url):
        fp = open(url, 'rb')
        parser = PDFParser(fp)
        doc = PDFDocument(parser)
        return doc.info  # The "Info" metadata
    def mine_doc(self,url):
        metadata = {}
        doc = docx.Document(url)
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

    def get_all_calls(self,url):
        print("retrieving ALL calls from the malware "+url)
        r2p = r2pipe.open(url)
        functions = r2p.cmd("aa;aflj")
        funcs = json.loads(functions)
        return funcs

    def get_api_calls(self,url):
        print("retrieving API calls from the malware "+url)
        r2p = r2pipe.open(url)
        apis = r2p.cmd("aa;aaa;axtj @@ sym.*")
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

    def get_headers(self,url):
        print("retrieving headers from the malware "+url)
        r2p = r2pipe.open(url)
        headers = r2p.cmd("aa;ij")
        headers = json.loads(headers)
        return headers


    def get_libraries(self,url):
        print("retrieving libraries from the malware "+url)
        r2p = r2pipe.open(url)
        libs = r2p.cmd("aa;ilj")
        return libs

    def get_network_ops(self,url):
        print("retrieving strings from the malware "+url)

        sa = Static_Extraction.StaticAnalysis(url)
        ipv4s = sa.get_ipv4_addresses()
        ipv6s = sa.get_ipv6_addresses()
        domains = sa.get_domains()
        urls = sa.get_urls()
        #r2p = r2pipe.open(url)
        #network = r2p.cmd("aa;izz")
        #urls = re.findall("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", network)
        network = ipv4s + ipv6s + domains + urls

        #r2p = r2pipe.open(url)
        #network = r2p.cmd("aa;izz")
        #ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", network)
        #urls = re.findall("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", network)
        #network = ips + urls

        return network

    def get_strings(self,url):
        print("retrieving headers from the malware "+url)
        r2p = r2pipe.open(url)
        strings = r2p.cmd("aaa;izj")
        return strings

    def get_entropy(self,url):
        binary = pefile.PE(url)
        entropy_dict = []
        for section in binary.sections:
            entropy_dict.append([str(section.Name).replace('\\x00', '').replace('b\'',''), hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData, section.get_entropy() ])
        return entropy_dict

    def get_imphash(self,url):
        file=pefile.PE(url)
        imphash = file.get_imphash()
        return imphash

    def get_impfuzzy(self,url):
        hsh = pyimpfuzzy.get_impfuzzy(url)
        return hsh
