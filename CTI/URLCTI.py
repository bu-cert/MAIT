from re import sub
import ssl
from CTI import virustotal_interface, threat_intel_platform_interface, alienvault_interface, securitytrails_interface, crt_sh_interface
import tldextract, configparser, json, ast, time

#A class which provides cyber threat intelligence for a given URL that has been extracted from a malware sample
class URL_CTI(): 
    def __init__(self, url):
        try: 
            self.url = url
            self.vti = virustotal_interface.virustotal_intelligence()
            self.tip = threat_intel_platform_interface.threat_intel_platform_intelligence()
            self.avi = alienvault_interface.alienvault_intelligence()
            self.sti = securitytrails_interface.securitytrails_intelligence()
            self.crt = crt_sh_interface.crtsh_ssl_scraper()
            self.domain_scan_results = self.get_domain_scan_results()[0]
        except Exception as error:
            print("Error occurred: " + "{0}".format(error))
        
    #Extracts the tld and sld from the given URL (E.g. google.com from http://docs.google.com)
    def extract_domain(self): 
        extracted_domain = tldextract.extract(self.url)
        tlds = extracted_domain[1] + "." + extracted_domain[2]

        return tlds

    #Gets the VirusTotal scan results of an extracted domain
    def get_domain_scan_results(self): 
        tlds = self.extract_domain()
        domain_scan_results = self.vti.virustotal_query_domain(tlds)  

        return domain_scan_results
    
    #Scans a URL and the extracted domain in VirusTotal and gets the reports 
    def scan_url(self): 
        url_report = self.vti.virustotal_scan_url(self.url)
        tlds = self.extract_domain()
        domain_report = self.vti.virustotal_scan_url(tlds)

        return url_report, domain_report

    #Gets the number of antiviruses that flag the extracted URL as malicious from VirusTotal
    def get_virustotal_score(self): 
        try: 
            url_scan_results = self.vti.virustotal_query_url(self.url)
            scan_id = str(url_scan_results[0]["scan_id"]).split("-")[0]
            url_report = json.loads('{"virustotal_url_report":"'+str(url_scan_results[0]["permalink"]).split("u-")[0]+'", "url":"'+self.url+'", "positives":"'+str(url_scan_results[0]["positives"])+'", "redirected_url":"'+str(self.vti.virustotal_v3_query_url(scan_id)[0]["data"]["attributes"]["last_final_url"])+'"}')
        except: 
            return json.loads('{"virustotal_url_report": {"error_occurred": '+json.dumps(url_scan_results)+'}}')

        return url_report

    #Gets subdomains associated with the extracted domain
    def get_subdomains(self):
        try: 
            subdomains = self.domain_scan_results
            subdomains = '{"subdomains":'+ json.dumps(subdomains["subdomains"]) +'}'
            subdomains = json.loads(subdomains)
        except: 
            return json.loads('{"virustotal_url_report": {"error_occurred": '+json.dumps(subdomains)+'}}')

        return subdomains

    #Translates the extracted domain to IP addresses
    def get_domain_ip_resolutions(self): 
        try: 
            ip_resolutions = self.domain_scan_results
            ip_resolutions = '{"ip_address_resolutions":'+ json.dumps(ip_resolutions["resolutions"]) +'}'
            ip_resolutions = json.loads(ip_resolutions)
        except: 
            return json.loads('{"virustotal_url_report": {"error_occurred": '+json.dumps(ip_resolutions)+'}}')

        return ip_resolutions

    #Gets latest and historical WHOIS records which includes information about the extracted domain, such as registrar and registration dates
    def get_domain_whois(self): 
        historical_whois = []
        try:
            whois_info = self.vti.virustotal_v3_query_domain(self.extract_domain(), "/historical_whois")
            whois_info = whois_info[0]["data"]
            for i in range(0, len(whois_info)): 
                historical_whois.append(whois_info[i]["attributes"])
            latest_whois = whois_info[0]["attributes"]

            whois_info = json.loads('{"whois_information": {"latest_whois":'+json.dumps(latest_whois)+', "historical_whois":'+json.dumps(historical_whois)+'}}')
        except: 
            return json.loads('{"whois_information": {"error_occurred": '+json.dumps(whois_info)+'}}')

        return whois_info
    
    #Gets DNS records such as A and MX records for the extracted domain
    def get_dns_info(self): 
        try: 
            domain = self.extract_domain()
            dns_info = self.sti.get_dns_records(domain)
            dns_info = '{"dns_records":'+json.dumps(dns_info['current_dns'])+'}'
            dns_info = json.loads(dns_info)   
        except: 
            return json.loads('{"dns_records": {"error_occurred": '+json.dumps(dns_info)+'}}')

        return dns_info

    #Gets hashes of potentially malicious files that are associated with the extracted domain
    def get_related_malicious_files(self): 
        malicious_files = 0
        try: 
            malicious_files = self.domain_scan_results

            #Potentially malicious files that have been downloaded from the given domain
            try: 
                detected_downloaded_samples = json.dumps(malicious_files["detected_downloaded_samples"])
            except KeyError:
                detected_downloaded_samples = '{"error_occurred": "No detected downloaded samples"}'

            #Potentially malicious files that include the given domain in their contents
            try: 
                detected_referrer_samples = json.dumps(malicious_files["detected_referrer_samples"])
            except KeyError:
                detected_referrer_samples = '{"error_occurred": "No detected referrer samples"}'

            #Potentially malicious files that contact the given domain in their contents
            try: 
                detected_communicating_samples = json.dumps(malicious_files["detected_communicating_samples"])
            except KeyError:
                detected_communicating_samples = '{"error_occurred": "No detected communicating samples"}'
        except: 
            return "Error occurred when retrieving related malicious files: " + str(malicious_files)#json.loads(r'{"related_malicious_files": {"error_occurred": '+json.dumps(malicious_files)+'}')

        related_malicious_files = json.loads('{"related_malicious_files": {"detected_downloaded_files":'+detected_downloaded_samples+', "detected_referrer_files":'+detected_referrer_samples+', "detected_communicating_files":'+detected_communicating_samples+'}}')

        return related_malicious_files

    #Gets potentially malicious URLs that are associated with the extracted domain
    def get_related_malicious_urls(self): 
        try: 
            detected_urls = self.domain_scan_results
            detected_urls = json.dumps(detected_urls["detected_urls"])
        except: 
            return json.loads('{"related_malicious_urls": {"error_occurred": '+json.dumps(self.domain_scan_results)+'}}')
        
        related_malicious_urls = json.loads('{"related_malicious_urls":'+detected_urls+'}')

        return related_malicious_urls

    #Gets historical SSL certificates from VirusTotal for an extracted domain
    def get_vt_historical_ssl_certs(self): 
        try: 
            domain = self.extract_domain()
            historical_ssl_certs = self.vti.virustotal_v3_query_domain(domain, "/historical_ssl_certificates")
            historical_ssl_certs = json.dumps(historical_ssl_certs[0]["data"])
            historical_ssl_certs = json.loads('{"vt_historical_ssl_certificates":'+historical_ssl_certs+'}')
        except: 
            return json.loads('{"vt_historical_ssl_certificates": {"error_occurred": '+json.dumps(historical_ssl_certs)+'}}')

        return historical_ssl_certs

    #Gets historical SSL certificates from Crt.sh for an extracted domain
    def get_crtsh_historical_ssl_certs(self): 
        try: 
            domain = self.extract_domain()
            domain_extension = str(domain).split(".")[1]
            for e in range(0,3): 
                try:
                    historical_ssl_certs = self.crt.get_crtsh_historical_ssl_certs(domain, domain_extension)
                    historical_ssl_certs = json.loads('{"crtsh_historical_ssl_certificates":'+historical_ssl_certs+'}')
                except Exception as err:
                    print(err)
                    time.sleep(12)
                    continue
                break
        except: 
            return json.loads('{"crtsh_historical_ssl_certificates": {"error_occurred": '+json.dumps(historical_ssl_certs)+'}}')

        return historical_ssl_certs

    #Get SSL Certificate information from threat intelligence platform for the extracted domain
    def get_ssl_config_info(self): 
        try: 
            domain = self.extract_domain()
            try:
                ssl_config_info = self.tip.query_domain_ssl_config(domain)
                ssl_config_info = json.dumps(ssl_config_info["testResults"])
            except: 
                ssl_cert_chain_report = self.tip.query_domain_ssl_cert_chain(domain)
                ssl_cert_chain_report = json.dumps(ssl_cert_chain_report)
                return json.loads('{"ssl_certificate_information": {"ssl_configuration": "No SSL certificate configuration data found", "ssl_certificate_chain":' +ssl_cert_chain_report+'}}')
            
            try: 
                ssl_cert_chain_report = self.tip.query_domain_ssl_cert_chain(domain)
                ssl_cert_chain_report = json.dumps(ssl_cert_chain_report)
            except: 
                ssl_config_info = self.tip.query_domain_ssl_config(domain)
                ssl_config_info = json.dumps(ssl_config_info["testResults"])
                return json.loads('{"ssl_certificate_information": {"ssl_configuration":'+ssl_config_info+', "ssl_certificate_chain": "No SSL certificate chain data found"}}')

            ssl_certificate_info = json.loads('{"ssl_certificate_information": {"ssl_configuration":'+ssl_config_info+', "ssl_certificate_chain":' +ssl_cert_chain_report+'}}')
        except:
            return json.loads('{"ssl_certificate_information": {"error_occurred":'+json.dumps(ssl_config_info)+', "error_occurred":'+json.dumps(ssl_cert_chain_report)+'}}')

        return ssl_certificate_info

    #Get the URL indicators from the related AlienVault pulses of the given URL
    def get_related_url_indicators(self): 
        url_indicators = []
        try: 
            indicator_report = self.avi.get_related_pulse_indicators(self.url, 'URL')

            for i in range(0, len(indicator_report)): 
                url_indicators.append({'pulse_id': indicator_report[i]['pulse_key'], 'indicator_id': indicator_report[i]['id'], 'indicator': indicator_report[i]['indicator'], 'type': indicator_report[i]['type'], 'created_date': indicator_report[i]['created']})

            url_indicators = json.loads('{"related_indicators_of_url":'+json.dumps(url_indicators)+'}')
        except Exception as error: 
            return json.loads('{"related_indicators_of_url": {"error_occurred": '+json.dumps('{0}'.format(error))+'}}')
        
        return url_indicators

    #Get the domain indicators from the related AlienVault pulses of the extracted domain    
    def get_related_domain_indicators(self): 
        domain_indicators = []
        try: 
            domain = self.extract_domain()
            indicator_report = self.avi.get_related_pulse_indicators(domain, 'domain')

            for i in range(0, len(indicator_report)): 
                domain_indicators.append({'pulse_id': indicator_report[i]['pulse_key'], 'indicator_id': indicator_report[i]['id'], 'indicator': indicator_report[i]['indicator'], 'type': indicator_report[i]['type'], 'created_date': indicator_report[i]['created']})

            domain_indicators = json.loads('{"related_indicators_of_domain":'+json.dumps(domain_indicators)+'}')
        except Exception as error: 
            return json.loads('{"related_indicators_of_domain": {"error_occurred": '+json.dumps('{0}'.format(error))+'}}')

        return domain_indicators

    #Checks for Google, Avast and ClamAV malicious alerts in AlienVault for the given URL
    def get_alienvault_alerts(self): 
        try: 
            alerts = self.avi.query_url(self.url)
            alerts = json.loads('{"antivirus_malicious_alerts":'+str(len(alerts[1]))+'}')
        except Exception as error:
            return json.loads('{"antivirus_malicious_alerts": {"error_occurred": '+json.dumps('{0}'.format(error))+'}}')

        return alerts

    #Gets information about related pulses such as threat group for the given URL
    def get_related_url_pulse_info(self): 
        url_pulse_info = []
        try: 
            pulse_report = self.avi.get_related_pulse_report(self.url, 'URL')

            for k in range(0, len(pulse_report)): 
                url_pulse_info.append({'pulse_id': pulse_report[k]['id'], 'name': pulse_report[k]['name'], 'adversary': pulse_report[k]['adversary'], 'attack_ids': pulse_report[k]['attack_ids'], 'tags': pulse_report[k]['tags']})

            url_pulse_info = json.dumps(url_pulse_info)
            url_pulse_info = '{"related_pulses_of_url":'+url_pulse_info+'}'
            url_pulse_info = json.loads(url_pulse_info)
        except Exception as error:
            return json.loads('{"related_pulses_of_url": {"error_occurred": '+json.dumps('{0}'.format(error))+'}}')

        return url_pulse_info

    #Gets information about related pulses such as threat group for the extracted domain
    def get_related_domain_pulse_info(self): 
        domain_pulse_info = []
        try: 
            domain = self.extract_domain()
            pulse_report = self.avi.get_related_pulse_report(domain, 'domain')

            for k in range(0, len(pulse_report)): 
                domain_pulse_info.append({'pulse_id': pulse_report[k]['id'], 'name': pulse_report[k]['name'], 'adversary': pulse_report[k]['adversary'], 'attack_ids': pulse_report[k]['attack_ids'], 'tags': pulse_report[k]['tags']})

            domain_pulse_info = json.dumps(domain_pulse_info)
            domain_pulse_info = '{"related_pulses_of_domain":'+domain_pulse_info+'}'
            domain_pulse_info = json.loads(domain_pulse_info)
        except Exception as error:
            return json.loads('{"related_pulses_of_domain": {"error_occurred": '+json.dumps('{0}'.format(error))+'}}')

        return domain_pulse_info