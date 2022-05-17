import os
import sys
import json
import urllib3
import urllib
import urllib.request
import hashlib
import argparse
import configparser
import requests
import time

class virustotal_intelligence():

    def __init__(self):
        config = configparser.ConfigParser()
        config.read('./config.txt')
        self.key = config['VirusTotal']['VIRUSTOTALKEY']
        self.url = config['VirusTotal']['VIRUSTOTALURL']   

    def request_get(self, url, data):
        try: 
            for e in range(0,3): 
                try:
                    request = urllib.request.Request(url, bytes(data, 'utf-8') )
                    response = urllib.request.urlopen(request)
                    report = json.loads(response.read())
                except Exception as err:
                    print("[!] ERROR: Cannot obtain results from VirusTotal: {0}\n".format(err))
                    time.sleep(20)
                    continue
                break

            results = []
            if type(report) is dict:
                results.append(report)
            elif type(report) is list:
                results = report
        except Exception as error:
            return json.dumps('{0}\n'.format(error))

        return results     

    def virustotal_scan(self, hash):
        url = self.url +'file/report'
        data = urllib.parse.urlencode({
            'resource' : hash,
            'apikey' : self.key
            })

        return self.request_get(url,data)

    #Scan URL or domain
    def virustotal_scan_url(self, url): 
        request_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
        data = urllib.parse.urlencode({
            'url' : url,
            'apikey' : self.key
            })
        
        return self.request_get(request_url,data)

    def virustotal_query_url(self, url):
        request_url = self.url+'url/report'
        data = urllib.parse.urlencode({
            'resource' : url,
            'apikey' : self.key
            })

        return self.request_get(request_url,data)
    
    def virustotal_v3_query_url(self, scan_id): 
        try:
            request_url = 'https://www.virustotal.com/api/v3/urls/' + scan_id
            headers = {'x-apikey': self.key}
            for e in range(0,3): 
                try:
                    response = requests.get(request_url, headers=headers)
                    report = response.json()
                except Exception as err:
                    print("[!] ERROR: Cannot obtain results from VirusTotal: {0}\n".format(err))
                    time.sleep(20)
                    continue
                break

            results = []
            if type(report) is dict:
                results.append(report)
            elif type(report) is list:
                results = report
        except Exception as error:
            return json.dumps('{0}\n'.format(error))

        return results

    def virustotal_query_ip(self, ip):
        try:
            request_url = self.url + "ip-address/report"
            params = {'apikey': self.key, 'ip': ip}
            for e in range(0,3): 
                try:
                    response = requests.get(request_url, params=params)
                    report = response.json()
                except Exception as err:
                    print("[!] ERROR: Cannot obtain results from VirusTotal: {0}\n".format(err))
                    time.sleep(20)
                    continue
                break

            results = []
            if type(report) is dict:
                results.append(report)
            elif type(report) is list:
                results = report
        except Exception as error:
            return json.dumps('{0}\n'.format(error))

        return results

    def virustotal_v3_query_ip(self, IP, relationship):
        try:
            request_url = 'https://www.virustotal.com/api/v3/ip_addresses/' + IP + relationship
            headers = {'x-apikey': self.key}
            for e in range(0,3): 
                try:
                    response = requests.get(request_url, headers=headers)
                    report = response.json()
                except:
                    time.sleep(20)
                    continue
                break

            results = []
            if type(report) is dict:
                results.append(report)
            elif type(report) is list:
                results = report

        except Exception as error:
            return json.dumps('{0}\n'.format(error))

        return results

    def virustotal_query_domain(self, domain):
        try:
            request_url = self.url +'domain/report'
            params = {'apikey':self.key,'domain':domain}
            for e in range(0,3):     
                try:
                    response = requests.get(request_url, params=params)
                    report = response.json()
                except Exception as err:
                    print("[!] ERROR: Cannot obtain results from VirusTotal: {0}\n".format(err))
                    time.sleep(20)
                    continue
                break

            results = []
            if type(report) is dict:
                results.append(report)
            elif type(report) is list:
                results = report
        except Exception as error:
            return json.dumps('{0}\n'.format(error))

        return results

    def virustotal_v3_query_domain(self, domain, relationship): 
        try:
            request_url = 'https://www.virustotal.com/api/v3/domains/' + domain + relationship
            headers = {'x-apikey': self.key}
            for e in range(0,3):         
                try:
                    response = requests.get(request_url, headers=headers)
                    report = response.json()
                except Exception as err:
                    print("[!] ERROR: Cannot obtain results from VirusTotal: {0}\n".format(err))
                    time.sleep(20)
                    continue
                break

            results = []
            if type(report) is dict:
                results.append(report)
            elif type(report) is list:
                results = report
        except Exception as error:
            return json.dumps('{0}\n'.format(error))

        return results