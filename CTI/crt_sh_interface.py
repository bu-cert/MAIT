from bs4 import BeautifulSoup
from urllib.request import urlopen
import json, re

class crtsh_ssl_scraper(): 
    def __init__(self):
        pass

    #Web scrape crt.sh for historical ssl certificates for a given domain
    def get_crtsh_historical_ssl_certs(self, domain, domain_extension): 
        try: 
            query_domain_url = 'https://crt.sh/?q=' + domain
            request = urlopen(query_domain_url)
            html = request.read()
            request.close()

            html_soup = BeautifulSoup(html, 'lxml')
            table = html_soup.select("table")[2]
            ssl_data = [[item.text for item in row_data.select('th,td')]
                        for row_data in table.select('tr')]

            #Remove column headings
            ssl_data.pop(0)

            ssl_json = []
            domain_extension = "("+domain_extension+")"

            cert_number = len(ssl_data)
            if len(ssl_data) > 20: 
                cert_number = 20


            for i in range(0, cert_number): 
                try: 
                    ssl_cert_data = self.query_crtsh_ssl_cert(ssl_data[i][0])
                except: 
                    ssl_json.append({"crtsh_id":ssl_data[i][0], "issued_date":ssl_data[i][1], "not_before":ssl_data[i][2], "not_after":ssl_data[i][3], "common_name":ssl_data[i][4], "sha-256":"error", "matching_identities":re.sub(domain_extension, r'\1 ', str(ssl_data[i][5])), "issuer_details":ssl_data[i][6], "certificate_revocation_checks":"error"})
                else: 
                    ssl_json.append({"crtsh_id":ssl_data[i][0], "issued_date":ssl_data[i][1], "not_before":ssl_data[i][2], "not_after":ssl_data[i][3], "common_name":ssl_data[i][4], "sha-256":ssl_cert_data[1], "matching_identities":re.sub(domain_extension, r'\1 ', str(ssl_data[i][5])), "issuer_details":ssl_data[i][6], "certificate_revocation_checks":ssl_cert_data[0]})

                ssl_certs_data = json.dumps(ssl_json)
        except Exception as error:
            return json.dumps('{0}'.format(error))

        return ssl_certs_data

    #Get details for the ssl certificate of the given crt.sh ID 
    def query_crtsh_ssl_cert(self, crt_sh_id): 
        query_ssl_cert_url = 'https://crt.sh/?id=' + crt_sh_id + '&opt=ocsp'
        request = urlopen(query_ssl_cert_url)
        html = request.read()
        request.close()

        html_soup = BeautifulSoup(html, 'lxml')
        table = html_soup.select("table")[1]
        ssl_data = [[item.text for item in row_data.select('th,td')]
                    for row_data in table.select('tr')]

        ssl_cert_checks = []

        #Range 10-15 will get all the revocation checks, 10-12 will just get OCSP and CRL
        for i in range(10,12):     
            ssl_cert_checks.append({"mechanism":ssl_data[i][0], "status":ssl_data[i][2], "revocation_date":ssl_data[i][3], "last_observed_in_crl":ssl_data[i][4], "last_checked":ssl_data[i][5]})

        sha256 = ssl_data[16][1]

        return ssl_cert_checks, sha256