import IndicatorTypes
from OTXv2 import OTXv2
import hashlib
import pprint
import time
import configparser
import py2neo
import json

class alienvault_intelligence:

    def __init__(self):
        config = configparser.ConfigParser()
        config.read('./config.txt')
        API_KEY = config['AlienVault']['API_KEY']
        OTX_SERVER = config['AlienVault']['OTX_SERVER']
        self.otx = OTXv2(API_KEY, server=OTX_SERVER)


    def query_hash(self, hash):
        result, alerts =  self.file( hash)
        return (result, alerts)


    def query_url(self, url):
        result, alerts =  self.url(url)
        if len(alerts) > 0:
            print('Identified as potentially malicious')
        else:
            print('Unknown or not identified as malicious')
        return (result, alerts)

    def query_domain(self, domain):
        result, alerts =  self.domain(domain)
        if len(alerts) > 0:
            print('Identified as potentially malicious')
        else:
            print('Unknown or not identified as malicious')
        return (result, alerts)

    def query_ip(self, ip, type):
        result, alerts =  self.ip(ip, type)
        if len(alerts) > 0:
            print('Identified as potentially malicious')
        else:
            print('Unknown or not identified as malicious')
        return (result, alerts)

    def insert_neo4j(self, neoGraph,savelst, hash256):
        neoSelector = py2neo. NodeMatcher(neoGraph)
        prevnode = ''
        if neoSelector.match("SAMPLE", sha1=hash256).first():
            print("Graph for sample %s already exists in Neo4j instance!" % hash256)
        else:
            node = py2neo.Node('SAMPLE', hash = hash256 )
            neoGraph.create(node)
            prevnode = node
        for i in savelst:    
            node1 = py2neo.Node(i[1], indicator = i[0], date = i[2] )
            neoGraph.create(node1)
            timerel = py2neo.Relationship(prevnode, 'next', node1)
            neoGraph.create(timerel)
            rootrel = py2neo.Relationship(node, i[1], node1)
            neoGraph.create(rootrel)
            prevnode = node1

    def get_hash_indicators(self, hash256):
        results, alerts = self.query_hash( hash256)
        pulses = results['general']['pulse_info']['pulses']

        savelst = []
        for i in pulses:
            pulse_detail = self.otx.get_pulse_details(i['id'])
            indicators = self.otx.get_pulse_indicators(i['id'])
            indicators = pulse_detail['indicators']
            for k in indicators:
                savelst.append((k['indicator'], k['type'] ,k['created']))
        return savelst

    def get_hash_pulses(self, hash256):
        results, alerts = self.query_hash(hash256)
        pulses = results['general']['pulse_info']['pulses']
        return pulses

    def get_url_pulses(self, mal_url):
        results, alerts = self.query_url(mal_url)
        pulses = results['general']['pulse_info']['pulses']
        return pulses

    def get_domain_pulses(self, mal_domain): 
        results, alerts = self.query_domain(mal_domain)
        pulses = results['general']['pulse_info']['pulses']
        return pulses

    def get_ip_pulses(self, mal_ip, type): 
        results, alerts = self.query_ip(mal_ip, type)
        pulses = results['pulse_info']['pulses']
        return pulses

        
    def get_url_indicators(self, url):
        results, alerts = self.query_url(url)
        pulses = results['general']['pulse_info']['pulses']

        savelst = []
        for i in pulses:
            pulse_detail = self.otx.get_pulse_details(i['id'])
            indicators = self.otx.get_pulse_indicators(i['id'])
            indicators = pulse_detail['indicators']
            for k in indicators:
                savelst.append((k['indicator'], k['type'] ,k['created']))
        return savelst

    def get_ip_indicators(self, IP):
        results, alerts = self.query_ip(IP)
        pulses = results['pulse_info']['pulses']
        savelst = []
        for i in pulses:
            pulse_detail = self.otx.get_pulse_details(i['id'])
            indicators = self.otx.get_pulse_indicators(i['id'])
            indicators = pulse_detail['indicators']
            for k in indicators:
                savelst.append((k['indicator'], k['type'] ,k['created']))
        return savelst

    def getValue(self, results, keys):
        if type(keys) is list and len(keys) > 0:

            if type(results) is dict:
                key = keys.pop(0)
                if key in results:
                    return self.getValue(results[key], keys)
                else:
                    return None
            else:
                if type(results) is list and len(results) > 0:
                    return self.getValue(results[0], keys)
                else:
                    return results
        else:
            return results

    def hostname(self,hostname):
        alerts = []
        result = self.otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, hostname, 'general')

        # Return nothing if it's in the whitelist
        validation = self.getValue(result, ['validation'])
        if not validation:
            pulses = self.getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append('In pulse: ' + pulse['name'])

        result = self.otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, hostname, 'general')
        # Return nothing if it's in the whitelist
        validation = self.getValue(result, ['validation'])
        if not validation:
            pulses = self.getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append('In pulse: ' + pulse['name'])
        return (result, alerts)


    def ip(self, ip, type):
        alerts = []
        if type == 'IPv4': 
            result = self.otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
        else: 
            result = self.otx.get_indicator_details_by_section(IndicatorTypes.IPv6, ip, 'general')
        # Return nothing if it's in the whitelist
        validation = self.getValue(result, ['validation'])
        if not validation:
            pulses = self.getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append('In pulse: ' + pulse['name'])

        return (result, alerts)

    def domain(self, domain):
        alerts = []
        result = self.otx.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)

        google = self.getValue( result, ['url_list', 'url_list', 'result', 'safebrowsing'])
        if google and 'response_code' in str(google):
            alerts.append({'google_safebrowsing': 'malicious'})


        clamav = self.getValue( result, ['url_list', 'url_list', 'result', 'multiav','matches','clamav'])
        if clamav:
                alerts.append({'clamav': clamav})

        avast = self.getValue( result, ['url_list', 'url_list', 'result', 'multiav','matches','avast'])
        if avast:
            alerts.append({'avast': avast})

        # Get the file analysis too, if it exists
        has_analysis = self.getValue( result,  ['url_list','url_list', 'result', 'urlworker', 'has_file_analysis'])
        if has_analysis:
            hash = self.getValue( result,  ['url_list','url_list', 'result', 'urlworker', 'sha256'])
            file_alerts = self.file(hash)
            if file_alerts:
                for alert in file_alerts:
                    alerts.append(alert)

        return (result, alerts)

    def url(self, url):
        alerts = []
        result = self.otx.get_indicator_details_full(IndicatorTypes.URL, url)

        google = self.getValue( result, ['url_list', 'url_list', 'result', 'safebrowsing'])
        if google and 'response_code' in str(google):
            alerts.append({'google_safebrowsing': 'malicious'})


        clamav = self.getValue( result, ['url_list', 'url_list', 'result', 'multiav','matches','clamav'])
        if clamav:
                alerts.append({'clamav': clamav})

        avast = self.getValue( result, ['url_list', 'url_list', 'result', 'multiav','matches','avast'])
        if avast:
            alerts.append({'avast': avast})

        # Get the file analysis too, if it exists
        has_analysis = self.getValue( result,  ['url_list','url_list', 'result', 'urlworker', 'has_file_analysis'])
        if has_analysis:
            hash = self.getValue( result,  ['url_list','url_list', 'result', 'urlworker', 'sha256'])
            file_alerts = self.file(hash)
            if file_alerts:
                for alert in file_alerts:
                    alerts.append(alert)

        # Todo: Check file page

        return (result, alerts)

    def file(self, hash):
        alerts = []
        hash_type = IndicatorTypes.FILE_HASH_MD5
        if len(hash) == 64:
            hash_type = IndicatorTypes.FILE_HASH_SHA256
        if len(hash) == 40:
            hash_type = IndicatorTypes.FILE_HASH_SHA1

        result = self.otx.get_indicator_details_full(hash_type, hash)
        avg = self.getValue( result, ['analysis','analysis','plugins','avg','results','detection'])
        if avg:
            alerts.append({'avg': avg})

        clamav = self.getValue( result, ['analysis','analysis','plugins','clamav','results','detection'])
        if clamav:
            alerts.append({'clamav': clamav})

        avast = self.getValue( result, ['analysis','analysis','plugins','avast','results','detection'])
        if avast:
            alerts.append({'avast': avast})

        microsoft = self.getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Microsoft','result'])
        if microsoft:
            alerts.append({'microsoft': microsoft})

        symantec = self.getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Symantec','result'])
        if symantec:
            alerts.append({'symantec': symantec})

        kaspersky = self.getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Kaspersky','result'])
        if kaspersky:
            alerts.append({'kaspersky': kaspersky})

        suricata = self.getValue( result, ['analysis','analysis','plugins','cuckoo','result','suricata','rules','name'])
        if suricata and 'trojan' in str(suricata).lower():
            alerts.append({'suricata': suricata})

        return (result, alerts)

    def get_related_pulse_report(self, indicator, type): 
        if type == 'URL': 
            pulse_report = self.get_url_pulses(indicator)
        elif type == 'domain': 
            pulse_report = self.get_domain_pulses(indicator)
        elif type == 'IPv4': 
            pulse_report = self.get_ip_pulses(indicator, 'IPv4')
        elif type == 'IPv6': 
            pulse_report = self.get_ip_pulses(indicator, 'IPv6')
        elif type == 'FileHash-SHA256': 
            pulse_report = self.get_hash_pulses(indicator)
        else: 
            return "Invalid indicator type"

        return pulse_report

    def get_related_pulse_indicators(self, indicator, type): 
        indicators = []
        pulse_report = self.get_related_pulse_report(indicator, type)

        for i in pulse_report: 
            pulse_indicators = self.otx.get_pulse_indicators(i['id'],limit = 300)

            for j in pulse_indicators:
                if j['type'] == type: 
                    indicators.append(j)
    
        indicators.sort(key = lambda x:x['created'])
        #for i in indicators:
            #print(i)
            #print(i['indicator'], i['created'])

        return indicators