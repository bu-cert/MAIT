import requests, json, configparser

class greynoise_intelligence():     
    def __init__(self): 

            config = configparser.ConfigParser()
            config.read('./config.txt')
            self.request_url = config['GreyNoise']['URL']

    def get_ip_intelligence(self, ip): 
        request_url = self.request_url + ip
        headers = {
            "Accept": "application/json",
            "User-Agent": "API-Reference-Test"
        }

        try: 
            response = requests.get(url=request_url, headers=headers)
            report = response.json()
        except Exception as error:
            return json.dumps('{0}\n'.format(error))

        return report