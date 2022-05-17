import os
import r2pipe
import networkx as nx
import json
import re
from datetime import datetime
from hashlib import sha1, md5, sha256
from os.path import basename, getsize
import magic
import pefile
import time
import math
import struct
from io import open
from collections import Counter
import py2neo 
import sys

def sha256hash(path):
	with open(path, 'rb') as f:
		return sha256(f.read()).hexdigest()

def sha1hash(path):
	with open(path, 'rb') as f:
		return sha1(f.read()).hexdigest() 

def md5hash(path):
	with open(path, 'rb') as f:
		return md5(f.read()).hexdigest()

def getFilename(path):
	return basename(path)

def getFiletype(path):
	return magic.from_file(path)

def getFilesize(path):
	return getsize(path)

def getPeSubsystem(path):
	pass


def getImphash(pe):
	return pe.get_imphash()

def getCompilationTS(pe):
	return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(pe.FILE_HEADER.TimeDateStamp))

def getEPAddress(pe):
	return pe.OPTIONAL_HEADER.AddressOfEntryPoint

def getSectionCount(pe):
	return pe.FILE_HEADER.NumberOfSections

def getOriginalFilename(pe):
	oriFilename = ""
	if hasattr(pe, 'VS_VERSIONINFO'):
		if hasattr(pe, 'FileInfo'):
			for entry in pe.FileInfo:
				if hasattr(entry, 'StringTable'):
					for st_entry in entry.StringTable:
						ofn = st_entry.entries.get(b'OriginalFilename')
						if ofn:
							if isinstance(ofn, bytes):
								oriFilename = ofn.decode()
							else:
								oriFilename = ofn
	return oriFilename


def getEPSection(pe):
	if hasattr(pe, 'OPTIONAL_HEADER'):
		ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	else:
		return False
	pos = 0
	for sec in pe.sections:
		if (ep >= sec.VirtualAddress) and (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
			sec.Name = sec.Name.replace(b'\x00', b'')
			name = sec.Name
			break
		else:
			pos += 1
	if name:
		return (str(name) + "|" + pos.__str__())
	return ''
		
def getTLSSectionCount(pe):
	idx = 0
	if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and pe.DIRECTORY_ENTRY_TLS.struct and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
		callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase

		while True:
			func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
			if func == 0:
				break
			idx += 1
	return idx


# Returns Entropy value for given data chunk
def Hvalue(data):
	if not data:
		return 0.0

	occurences = Counter(bytearray(data))
	
	entropy = 0
	for x in occurences.values():
		p_x = float(x) / len(data)
		if p_x > 0:
			entropy += - p_x * math.log(p_x, 2)

	return entropy


def getCodeSectionSize(pe):

	for section in pe.sections:
		print(section)


def getSectionInfo(pe):
	sects = []
	vadd = []
	ent = []
	secnumber = getSectionCount(pe)
	
	for i in range(12):

		if (i + 1 > secnumber):
			strip = ""
			strap = ""
			entropy = ""

		else:
			stuff = pe.sections[i]
			strip = stuff.Name.replace(b'\x00', b'')
			strap = stuff.SizeOfRawData

			entropy = Hvalue(stuff.get_data())

		section_name = ""
		try:
			if strip != "":
				section_name = strip.decode()
		except:
			section_name = "PARSINGERR"

		sects.append(section_name)
		ent.append(entropy)
		vadd.append(strap)

	secinfo = sects + vadd + ent
	return secinfo

	
# ATTRIBUTES: md5, sha1, filename, filetype, ssdeep, filesize, imphash, compilationts, addressep, sectionep,
# sectioncount, sectioninfo, tlssections, originalfilename
	
def getAllAttributes(path):

	allAtts = {}

	allAtts['md5'] = md5hash(path)
	allAtts['sha256'] = sha256hash(path)
	allAtts['filename'] = getFilename(path)
	allAtts['fname'] = path.replace("sample/","")
	allAtts['filetype'] = getFiletype(path)
	allAtts['filesize'] = getFilesize(path)

	try:
		pe = pefile.PE(path)
		if (pe.DOS_HEADER.e_magic == int(0x5a4d) and pe.NT_HEADERS.Signature == int(0x4550)):
			allAtts['imphash'] = getImphash(pe)
			allAtts['compilationts'] = getCompilationTS(pe)
			allAtts['addressep'] = getEPAddress(pe)
			allAtts['sectionep'] = getEPSection(pe)
			allAtts['sectioncount'] = getSectionCount(pe)
			allAtts['sectioninfo'] = getSectionInfo(pe)
			allAtts['tlssections'] = getTLSSectionCount(pe)
			allAtts['originalfilename'] = getOriginalFilename(pe)

	except (pefile.PEFormatError):
		allAtts['imphash'] = ''
		allAtts['compilationts'] = ''
		allAtts['addressep'] = ''
		allAtts['sectionep'] = ''
		allAtts['sectioncount'] = ''
		allAtts['sectioninfo'] = ''
		allAtts['tlssections'] = ''
		allAtts['originalfilename'] = ''

	return allAtts

#neo4j functions


def toNeo(neoGraph,graphity, allAtts):

	### NetworkX Graph Structure ###

	# FUNCTION as node, attributes: function address, size, calltype, list of calls, list of strings, count of calls; functiontype[Standard, Callback, Export], alias (e.g. export name)
	# FUNCTIoN REFERENCE as edge (function address -> target address), attributes: ref offset (at)
	# CALLBACK REFERENCE as edge (currently for threads and Windows hooks)
	# API CALLS (list attribute of function node): address, API name
	# STRINGS (list attribute of function node): address, string

	####

	
	neoSelector = py2neo. NodeMatcher(neoGraph)

	# flush of the DB, for test purposes
	#neoGraph.delete_all()

	mySha1 = allAtts['sha256']

	if neoSelector.match("SAMPLE", sha256=mySha1).first():
		print("Graph for sample %s already exists in Neo4j instance!" % mySha1)

	else:

		# create master node for binary information
		sampleNode = py2neo.Node("SAMPLE", sha256=mySha1,fname=allAtts['fname'] ,fileSize=allAtts['filesize'], binType=allAtts['filetype'], imphash=allAtts['imphash'], compilation=allAtts['compilationts'], addressEp=allAtts['addressep'], sectionEp=allAtts['sectionep'], sectionCount=allAtts['sectioncount'], originalFilename=allAtts['originalfilename'])
		neoGraph.create(sampleNode)

		# get nodes with 0 indegree, prepare relations from master node 
		indegrees = graphity.in_degree()
		rootlist = []
		for val in indegrees:
			if val[1] == 0:
				rootlist.append(val[0])

		# parsing of the NetworkX graph - functions, APIs and strings are all Neo4j nodes
		for nxNode in graphity.nodes(data=True):

			funcAddress = nxNode[0]
			funcCalltype = nxNode[1]['calltype']
			funcSize = nxNode[1]['size']
			funcAlias = ''
			funcType = ''
			fout_degree = 0
			fin_degree = 0
			fapicalls = 0
			if nxNode[1].get('functiontype') : 
				funcType = nxNode[1]['functiontype']

			functionNode = py2neo.Node("FUNCTION", sample=mySha1, address=funcAddress, callType=funcCalltype, funcSize=funcSize, funcType=funcType, alias=funcAddress, out_degree=fout_degree, in_degree=fin_degree, apicalls=fapicalls)
			neoGraph.create(functionNode)
			
			if funcAddress in rootlist:
				rootrel = py2neo.Relationship(sampleNode, "STARTS", functionNode)
				neoGraph.create(rootrel)

		
			callsList = nxNode[1]['calls']
			for callData in callsList:
				callRefAddress = callData[0]
				callApiName = callData[1]

				# create API node or merge if API already exists, add relationship
				apiNode = py2neo.Node("API", apiname=callApiName)
				
				neoGraph.create(apiNode)

				apiRel = py2neo.Relationship(functionNode, "IMPORTS", apiNode, address=callRefAddress)
				neoGraph.create(apiRel)
				functionNode["apicalls"] += 1
				neoGraph.push(functionNode)

		for from_node, to_node, properties in graphity.edges(data=True):

			realFromNode = neoSelector.match("FUNCTION", sample=mySha1, address=from_node).first()
			realToNode = neoSelector.match("FUNCTION", sample=mySha1, address=to_node).first()

			funcCallsFunc =  py2neo.Relationship(realFromNode, "CALLS", realToNode, at_address=properties['pos'], distance=hex(abs(int(to_node,16)-int(from_node,16))) )
			
			neoGraph.create(funcCallsFunc)
			realFromNode["out_degree"] +=  1
			realToNode["in_degree"] +=  1
			neoGraph.push(realFromNode)
			neoGraph.push(realToNode)

def gimmeRespectiveFunction(R2PY, address):
	if address:
		return R2PY.cmd("?v $FB @" + address)
	return ''


def gimmeDatApiName(wholeString):

	separators = ['.dll_', '.sys_', '.exe_', '.sym_']

	for sep in separators:

		if sep in wholeString:
			apiName = wholeString.split(sep)[1].replace(']','')
			return apiName

		elif sep.upper() in wholeString:
			apiName = wholeString.split(sep.upper())[1].replace(']','')
			return apiName

	return wholeString	



# Returns a list of executable sections
def getCodeSections(R2PY):
	returnSections = []
	# regular expression to pick out the executable section(s)
	execSection = re.compile("perm=....x")
	# will return the section table from radare2
	sections = R2PY.cmd("iS")
	sectionData = {}
	for line in sections.splitlines():
		if re.search(execSection, line):
			for element in line.split():
				items = element.split('=')
				sectionData[items[0]] = items[1]

			start = int(sectionData['vaddr'], 16)
			end = start + int(sectionData['vsz'])
			psize = int(sectionData['sz'])
			returnSections.append([start, end, psize])
	return returnSections




# Returns an executables imports as a list
def getIat(R2PY):

	iatlist = []
	cmd = "iij"
	iatjson = json.loads(R2PY.cmd(cmd))
	for item in iatjson:
		iatlist.append(hex(item['plt']))
	return iatlist





def run_all(neoGraph, url):
	debugDict = {}
	graphity = nx.DiGraph()

	r2p = r2pipe.open(url)
	r2p.cmd("e asm.lines = false")
	r2p.cmd("e anal.autoname= false")
	r2p.cmd("e anal.hasnext = true")
	r2p.cmd("aaa")

	functions = r2p.cmd("aflj")
	if functions:
		functionList=json.loads(functions)
	else:
		functionList = []
	# figuring out code section size total
	sectionsList = getCodeSections(r2p)
	xlen = 0
	for execSec in sectionsList:
		xlen = xlen + execSec[2]
	
	debugDict['xsectionsize'] = xlen
	debugDict['functions'] = len(functionList)
	
	# CREATING THE GRAPH
	for item in functionList:
		graphity.add_node(hex(item['offset']), size=item['realsz'], calltype=item['calltype'], calls=[], apicallcount=0, strings=[], stringcount=0, functiontype='')

	for item in functionList:
		try:
			for xref in item['callrefs']:
				if xref['type'] == 'CALL':
					if hex(xref['addr']) in graphity:
						if item['offset'] != xref['addr']:
							graphity.add_edge(hex(item['offset']), hex(xref['addr']), pos=hex(xref['at']))
					elif hex(xref['addr']) in getIat(r2p):
						pass
					elif not isValidCode(hex(xref['addr']), sectionsList):
						print("DANGLING call to address outside code section, glob var, dynamic API loading %s -> %s" % (hex(item['offset']), hex(xref['addr'])))
					else:
						print("FAIL: Call to code thats not a function, an import/symbol or otherwise recognized. Missed function perhaps. %s -> %s" % (hex(item['offset']), hex(xref['addr'])))
		except:
			pass

	print('* %s Graph created with NetworkX ' % str(datetime.now()))


#API REF
	cmd = "axtj @@ sym.*"
	finalCalls = {}

	# fixing the JSON... issue reported to radare2, keep in mind to remove workaround
	
	temp = r2p.cmd(cmd)
	apilines = temp.split('\n')
	data = ''
	first = 0
	for line in apilines:

		if line[1:-1] != '':
			if first == 0:
				first = 1

				data = data + line[1:-1] 
			else:
				data = data  + ','+ line[1:-1] 
	data = "[" + data + "]"
	xrefj = json.loads(data)

	for xrefitem in xrefj:
			# not data xref means its code or call
			if xrefitem['type'] != 'd':
				finalCalls[hex(xrefitem['from'])] = xrefitem['opcode']
				pass

			# data potentially means API referenced by register; please note these are rather uncommon in the long list of symbol refs
			# thus, bottelneck in parsing speed lies in number of refs
			if xrefitem['type'] == 'd' and ( xrefitem['opcode'].startswith('mov') or xrefitem['opcode'].startswith('lea') ):

				# 'grepping' out the register from mov/lea operation
				register = xrefitem['opcode'].split()[1].replace(',','')

				# disassemble downwards; mmmaybe smarter to disassemble until end of function, but possible that there is no function at all
				# TODO find end of function, just in case
				cmd = "pd 300 @ " + hex(xrefitem['from'])
				moreDisasm = r2p.cmd(cmd)

				# possible branches towards target
				realCall = "call %s" % register
				aJmp = "jmp %s" % register

				for disasmLine in moreDisasm.splitlines()[1:]:
					if realCall in disasmLine or aJmp in disasmLine:
						temp = disasmLine + ";" + xrefitem['opcode'].split(',')[1].rstrip()
						tempSplit = temp.split()
						finalCalls[hex(int(tempSplit[0], 16))] = ' '.join(tempSplit[1:])
	apiRefs = finalCalls
	callNum = len(apiRefs)
	missesNum = 0

	for call in apiRefs:

		# get the address of the function, that contains the call to a given symbol
		funcAddress = gimmeRespectiveFunction(r2p, call)
		# TODO check if funcAddress is the real function address
		
		if funcAddress in graphity:

			# node(funcAddress) has attribute calls, which contains a list of API calls
			api = gimmeDatApiName(apiRefs[call])

			graphity.node[funcAddress]['calls'].append([call, api])
			graphity.node[funcAddress]['apicallcount']+= 1
			
		# detected API call reference does not resolve to a function offset, insert handling for this here
		else:
			print("DANGLING API CALL %s %s" % (call, apiRefs[call]))
			missesNum = missesNum+1

	# debug: print total API refs and functionless API refs, maybe indicator for obfuscated code
	print('* %s Graph extended with API calls, %d calls in total, %d dangling w/o function reference ' % (str(datetime.now()), callNum, missesNum))
	debugDict['apiTotal'] = callNum
	debugDict['apiMisses'] = missesNum
	toNeo(neoGraph,graphity, getAllAttributes(url))
