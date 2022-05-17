from . import alienvault_interface
from . import virustotal_interface
from . import abusech_interface
from OTXv2 import OTXv2
import configparser
import py2neo


class APT_Intelligence:

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


  
    
    def AlienVault_Tags(self, urlhash):
        visit_list = []
        self.adversary_list = []
        self.tag_list = []
        pulses = self.av.get_hash_pulses(urlhash)
        for i in pulses:
            pulse_detail = self.otx.get_pulse_details(i['id'])
            print(i['id'], '-',pulse_detail['adversary'],'-' ,pulse_detail['tags'])
            indicators = self.otx.get_pulse_indicators(i['id'])
            for j in indicators:
                self.indicator_list.append(j['id'])
                if 'FileHash' in j['type']: 
                    new_pulses = alienvault_interface.get_hash_pulses(j['indicator'])
                    for k in new_pulses:
                        if k['id'] not in visit_list:
                            self.pulse_recursion(k['id'], visit_list, 0 )
                            visit_list.append(k['id'])
        print('tags:', self.tag_list)
        print('adversaries:', self.adversary_list)
        return

################################################################
    def AlienVault_Tags_for_URL(self, mal_url):
        visit_list = []
        self.adversary_list = []
        self.tag_list = []
        pulses = self.av.get_url_pulses(mal_url)
        for i in pulses:
            pulse_detail = self.otx.get_pulse_details(i['id'])
            print(i['id'], '-',pulse_detail['adversary'],'-' ,pulse_detail['tags'])
            indicators = self.otx.get_pulse_indicators(i['id'])
            for j in indicators:
                self.indicator_list.append(j['id'])
                if 'FileHash' in j['type']: 
                    new_pulses = alienvault_interface.get_url_pulses(j['indicator'])
                    for k in new_pulses:
                        if k['id'] not in visit_list:
                            self.pulse_recursion(k['id'], visit_list, 0 )
                            visit_list.append(k['id'])
        print('tags:', self.tag_list)
        print('adversaries:', self.adversary_list)
        return

    def pulse_recursion_url(self, pulse_id, visit_list, level ):
        if level == self.depth:
            print('max depth is reached, returning')
            return
        elif pulse_id in visit_list:
            print('pulse is encountered before, returning')
            return
        else:
            visit_list.append(pulse_id)
            pulse_detail = self.otx.get_pulse_details(pulse_id)
            print(pulse_id, '-',pulse_detail['adversary'],'-' ,pulse_detail['tags'])
            
            if pulse_detail['tags']:
                self.tag_list = self.tag_list + pulse_detail['tags']

            if pulse_detail['adversary']:
                self.adversary_list.append(pulse_detail['adversary'])
            indicators = self.otx.get_pulse_indicators(pulse_id)
            for i in indicators:
                if i not in self.indicator_list:
                    if 'FileHash' in i['type']: 
                        new_pulses = alienvault_interface.get_url_pulses(i['indicator'])
                        for j in new_pulses:
                            if j['id'] not in visit_list:
                                self.pulse_recursion_url(j['id'], visit_list, level+1)
            return
####################################################################



    def find_apt_name(self, urlhash):
        pulses = self.av.get_hash_pulses(urlhash)
        advlst = []
        for i in pulses:
            if i['adversary']:
                advlst.append(i['adversary'])
            
            indicators = self.otx.get_pulse_indicators(i['id'])
            count = 0
            for j in indicators:
                if count > 50:
                    break
                count += 1
                try:
                    new_pulses = alienvault_interface.get_hash_pulses(j['indicator'])
                    for k in new_pulses:
                        if k['adversary']:
                            advlst.append(k['adversary'])       
                except:
                    pass
        return list(set(advlst))


    
    def pulse_recursion(self, pulse_id, visit_list, level ):
        if level == self.depth:
            print('max depth is reached, returning')
            return
        elif pulse_id in visit_list:
            print('pulse is encountered before, returning')
            return
        else:
            visit_list.append(pulse_id)
            pulse_detail = self.otx.get_pulse_details(pulse_id)
            print(pulse_id, '-',pulse_detail['adversary'],'-' ,pulse_detail['tags'])
            
            if pulse_detail['tags']:
                self.tag_list = self.tag_list + pulse_detail['tags']

            if pulse_detail['adversary']:
                self.adversary_list.append(pulse_detail['adversary'])


            indicators = self.otx.get_pulse_indicators(pulse_id)

            for i in indicators:
                if i not in self.indicator_list:
                    if 'FileHash' in i['type']: 
                        new_pulses = alienvault_interface.get_hash_pulses(i['indicator'])
                        for j in new_pulses:
                            if j['id'] not in visit_list:
                                self.pulse_recursion(j['id'], visit_list, level+1)
            return
                            


    def hash_recursion(self, urlhash, visited_list):
        if urlhash in visited_list:
            print('hash is encountered before, returning')
            return 
        else:
            visited_list.append(urlhash)
            pulses = self.av.get_hash_pulses(urlhash)
            for i in pulses:
                indicators = self.otx.get_pulse_indicators(i['id'])
                for j in indicators:
                    if 'FileHash' in j['type']: 
                        print(j['title'],j['type'] ,j['indicator'])
                        self.hash_recursion(j['indicator'], visited_list)



    def AlienVault_TTPs(self, urlhash):
        pulses = self.av.get_hash_pulses(urlhash)
        advlst = []
        for i in pulses:
            if i['attack_ids']:
                for j in i['attack_ids']:
                    advlst.append((j['id'], ' - ', j['name']))
        return advlst

    def AlienVault_TTPs_forURL(self, mal_url):
        pulses = self.av.get_url_pulses(mal_url)
        advlst = []
        for i in pulses:
            if i['attack_ids']:
                for j in i['attack_ids']:
                    advlst.append(j['id'], ' - ', j['name'])
          
        return advlst

    def malwarebazaar_tags_intel(self, urlhash):
        s = self.ach.malwarebazaar_hash(urlhash)
        tags = []
        intel = {}
        for i in s:
            if i['query_status'] == 'ok':
                for j in i['data']:
                    for key,value in j.items():
                        if key == 'tags':
                            tags = tags + value
                        if key == 'vendor_intel':
                            intel.update(value)
        return tags,intel 

    

