from . import alienvault_interface
from . import virustotal_interface
from . import abusech_interface
from OTXv2 import OTXv2
import configparser
import py2neo
import json


class Create_Nav:
    
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

    def AlienVault_TTPs(self, urlhash):
        pulses = self.av.get_hash_pulses(urlhash)
        advlst = []
        for i in pulses:
            if i['attack_ids']:
                for j in i['attack_ids']:
                    advlst.append(  {'score':1, 'techniqueID':j['id'], 'showSubtechniques': True}  )
        return advlst

    def get_cuckoo_ttps(self, ttps): 
        ttplst = []
        ttp_ids = []
        ttps = ttps['ttps']

        #Need to get a list of the TTP IDs using a separate for loop, as each list item can have multiple TTP IDs
        for ttp in range(0, len(ttps)): 
            ttp_ids = list(ttps[ttp].keys()) + ttp_ids
        print(ttp_ids)

        for i in range(0, len(ttp_ids)): #FIXME: Does not highlight subtechniques 
            ttplst.append( {'score':1, 'techniqueID':ttp_ids[i], 'showSubtechniques': True} )

        return ttplst