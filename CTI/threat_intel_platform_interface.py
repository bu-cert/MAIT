import requests, configparser, json

class threat_intel_platform_intelligence(): 

    def __init__(self):
        config = configparser.ConfigParser()
        config.read('./config.txt')
        self.key = config['ThreatIntelligencePlatform']['API_KEY']
        self.url = config['ThreatIntelligencePlatform']['URL']

    def query_domain_ssl_config(self, domain): 
        try: 
            request_url = self.url + 'sslConfiguration?domainName=' + domain + '&apiKey=' + self.key
            response = requests.get(request_url)
            report = response.json()
        except Exception as error:
            return json.dumps('{0}\n'.format(error))

        return report

    def query_domain_ssl_cert_chain(self, domain): 
        try: 
            request_url = self.url + 'sslCertificatesChain?domainName=' + domain + '&apiKey=' + self.key
            response = requests.get(request_url)
            report = response.json()
        except Exception as error:
            return json.dumps('{0}\n'.format(error))

        return report   

