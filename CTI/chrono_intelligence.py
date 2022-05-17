from . import alienvault_interface
from . import virustotal_interface
from . import abusech_interface
from OTXv2 import OTXv2
import IndicatorTypes
import configparser
import py2neo


class Chrono_Intelligence:

    def __init__(self):
        config = configparser.ConfigParser()
        config.read('./config.txt')
        API_KEY = config['AlienVault']['API_KEY']
        OTX_SERVER = config['AlienVault']['OTX_SERVER']
        self.otx = OTXv2(API_KEY, server=OTX_SERVER)

        self.adversary_list = []
        self.tag_list = []
        self.indicator_list = []
        self.depth = 10
        self.av = alienvault_interface.alienvault_intelligence()
        self.ach = abusech_interface.abusech_intelligence()
        self.vt = virustotal_interface.virustotal_intelligence()

    def malware_first_seen(self, urlhash):
        #OTX
        retlst = []
        ind_details = self.otx.get_indicator_details_by_section(IndicatorTypes.FILE_HASH_SHA256, urlhash)
        if ind_details['pulse_info']:
            lent = ind_details['pulse_info']['count']
            for i in range(0,lent):
                pulse = ind_details['pulse_info']['pulses'][i]
                retlst.append((pulse['name'], pulse['created']))
                if pulse['references']:
                    print('References')
                    for i in pulse['references']:
                        retlst.append(i)
        
        #malware bazaar
        s = self.ach.malwarebazaar_hash(urlhash)
        intel = {}
        for i in s:
            if i['query_status'] == 'ok':
                for j in i['data']:
                    for key,value in j.items():
                        if key == 'vendor_intel':
                            intel.update(value)
        for key,value in intel.items():
            retlst.append((key, '-', value))
        return  retlst 

    def virustotal_dates(self, urlhash):
        scan = self.vt.virustotal_scan(urlhash)
        lst = []
        
        for i in scan:
        	if i['response_code'] != 0:
        		for key,value in i['scans'].items():
        			lst.append([key,  value['update']])
        return lst
