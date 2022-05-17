import configparser, requests, json

class securitytrails_intelligence():     
    def __init__(self): 
        config = configparser.ConfigParser()
        config.read('./config.txt')
        self.key = config['SecurityTrails']['API_KEY']
        self.request_url = config['SecurityTrails']['URL']

    def get_dns_records(self, domain): 
        try: 
            request_url = self.request_url + 'domain/' + domain
            headers = {
            "Accept": "application/json",
            "APIKEY": self.key
            }
            
            response = requests.get(url=request_url, headers=headers)
            report = response.json()

        except Exception as error:
            return json.dumps('{0}'.format(error))

        return report