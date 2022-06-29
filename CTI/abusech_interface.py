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



class abusech_intelligence:

    def __init__(self):
        config = configparser.ConfigParser()
        config.read('./config.txt')
        self.url_mb = config['MalwareBazaar']['URL']
        self.url_ach = config['AbuseCh']['URL']

    def request_get(self, url, data):
        try:
            request = urllib.request.Request(url, bytes(data, 'utf-8') )
            response = urllib.request.urlopen(request)
            report = json.loads(response.read())
        except Exception as e:
            print("[!] ERROR: Cannot obtain results from VirusTotal: {0}\n".format(e))
            return
        results = []
        if type(report) is dict:
            results.append(report)
        elif type(report) is list:
            results = report
        return results

    def malwarebazaar_hash(self,hash):
        data = urllib.parse.urlencode({
            'query' : 'get_info',
            'hash': hash
            })
        return self.request_get( self.url_mb, data)

    def malwarebazaar_imphash(self,imphash):
        data = urllib.parse.urlencode({
            'query' : 'get_imphash',
            'imphash': imphash,
            'limit':1000
            })
        return self.request_get(self.url_mb, data)

    def urlhaus_hostscan(self,host):
        url = self.url_ach+'host/'
        data = urllib.parse.urlencode({
            'host' : host,
            })
        return self.request_get(url, data)

    def urlhaus_urlscan(self,url):
        endpoint_url = self.url_ach+'url/'
        data = urllib.parse.urlencode({
            'url' : url,
            })
        return self.request_get(endpoint_url, data)

    def urlhaus_scan(self,hash):
        url = self.url_ach+'payload/'
        data = urllib.parse.urlencode({
            'sha256_hash' : hash,
            })
        return self.request_get(url, data)
