from CTI import virustotal_interface, alienvault_interface, greynoise_interface
import urllib.request, json, configparser, requests, dnsdb

#A class which provides cyber threat intelligence for a given IP address that has been extracted from a malware sample
class IP_CTI(): 
    def __init__(self, ip):
        try: 
            self.ip = ip
            self.vti = virustotal_interface.virustotal_intelligence()
            self.avi = alienvault_interface.alienvault_intelligence()
            self.gni = greynoise_interface.greynoise_intelligence()
            self.ip_scan_results = self.get_ip_scan_results()
        except Exception as error:
            print("Error occurred: " + "{0}".format(error))

    #Get VirusTotal v2 IP address scan results
    def get_ip_scan_results(self): 
        virustotal_v2_ip_report = self.vti.virustotal_query_ip(self.ip)
        
        return virustotal_v2_ip_report

    #Gets the antivirus results from VirusTotal for the extracted IP address
    def get_virustotal_score(self): 
        try: 
            ip_scan_results = self.vti.virustotal_v3_query_ip(self.ip, "")
            ip_scan_results = ip_scan_results[0]["data"]
            ip_report = json.loads('{"virustotal_ip_address_report":"'+str(ip_scan_results["links"]["self"])+'", "ip_address":"'+self.ip+'", "malicious":"'+str(ip_scan_results["attributes"]["last_analysis_stats"]["malicious"])+'", "suspicious":"'+str(ip_scan_results["attributes"]["last_analysis_stats"]["suspicious"])+'"}')
        except: 
            return json.loads('{"virustotal_ip_address_report": {"error_occurred": '+json.dumps(ip_scan_results)+'}}')

        return ip_report

    #Gets the hostname resolutions for the given IP address
    def get_hostname_resolutions(self): 
        hostname_resolutions = []
        try: 
            ip_address_report = self.vti.virustotal_v3_query_ip(self.ip, "/resolutions")[0]["data"]
            for i in range(0, len(ip_address_report)): 
                hostname_resolutions.append({'date': ip_address_report[i]["attributes"]["date"], 'hostname': ip_address_report[i]["attributes"]["host_name"], 'resolver': ip_address_report[i]["attributes"]["resolver"]})

            hostname_resolutions = json.loads('{"hostname_resolutions":'+json.dumps(hostname_resolutions)+'}')
        except: 
            return json.loads('{"hostname_resolutions": {"error_occurred": '+json.dumps(self.ip_scan_results)+'}}')

        return hostname_resolutions

    #Gets latest and historical WHOIS records for the given IP address
    def get_ip_whois(self): 
        historical_whois = []
        try:
            whois_info = self.vti.virustotal_v3_query_ip(self.ip, "/historical_whois")
            whois_info = whois_info[0]["data"]
            for i in range(0, len(whois_info)): 
                historical_whois.append(whois_info[i]["attributes"])
            latest_whois = whois_info[0]["attributes"]

            whois_info = json.loads('{"whois_information": {"latest_whois":'+json.dumps(latest_whois)+', "historical_whois":'+json.dumps(historical_whois)+'}}')
        except: 
            return json.loads('{"whois_information": {"error_occurred": '+json.dumps(whois_info)+'}}')

        return whois_info

    #Gets hashes of potentially malicious files that are associated with the given IP address
    def get_related_malicious_files(self): 
        malicious_files = 0
        try: 
            malicious_files = self.ip_scan_results

            #Potentially malicious files that have been downloaded from the given domain
            try: 
                detected_downloaded_samples = json.dumps(malicious_files[0]["detected_downloaded_samples"])
            except KeyError:
                detected_downloaded_samples = '{"error_occurred": "No detected downloaded samples"}'

            #Potentially malicious files that include the given domain in their contents
            try: 
                detected_referrer_samples = json.dumps(malicious_files[0]["detected_referrer_samples"])
            except KeyError:
                detected_referrer_samples = '{"error_occurred": "No detected referrer samples"}'

            #Potentially malicious files that contact the given domain in their contents
            try: 
                detected_communicating_samples = json.dumps(malicious_files[0]["detected_communicating_samples"])
            except KeyError:
                detected_communicating_samples = '{"error_occurred": "No detected communicating samples"}'
        except: 
            return json.loads('{"related_malicious_files": {"error_occurred": '+json.dumps(malicious_files)+'}}')
        
        related_malicious_files = json.loads('{"related_malicious_files": {"detected_downloaded_files":'+detected_downloaded_samples+', "detected_referrer_files":'+detected_referrer_samples+', "detected_communicating_files":'+detected_communicating_samples+'}}')

        return related_malicious_files

    #Gets potentially malicious URLs that are associated with the given IP address
    def get_related_malicious_urls(self): 
        try: 
            detected_urls = self.ip_scan_results
            detected_urls = json.dumps(detected_urls[0]["detected_urls"])
        except:
            return json.loads('{"related_malicious_urls": {"error_occurred": '+detected_urls+'}}')

        related_malicious_urls = json.loads('{"related_malicious_urls":'+detected_urls+'}')

        return related_malicious_urls

    #Gets historical SSL certificates for the given IP address
    def get_historical_ssl_certs(self): 
        try: 
            historical_ssl_certs = self.vti.virustotal_v3_query_ip(self.ip, "/historical_ssl_certificates")
            historical_ssl_certs = json.dumps(historical_ssl_certs[0]["data"])
            historical_ssl_certs = json.loads('{"historical_ssl_certificates":'+historical_ssl_certs+'}')
        except:
            return json.loads('{"historical_ssl_certificates": {"error_occurred": '+historical_ssl_certs+'}}')

        return historical_ssl_certs

    #Gets geolocation information for the extracted IP address (longitude and latitude primarily)
    def get_ip_geolocation(self): 
        try: 
            response = urllib.request.urlopen("https://ipwhois.app/json/"+self.ip)
            ipgeolocation = json.load(response)
            ip_proxy_info = self.get_ip_proxy_info()

            ip_geolocation_info = json.loads('{"ip_geolocation_info": {"country_code":'+json.dumps(ipgeolocation["country_code"])+', "city_name":'+json.dumps(ipgeolocation["city"])+', "latitude":'+json.dumps(ipgeolocation["latitude"])+', "longitude":'+json.dumps(ipgeolocation["longitude"])+',"isp":'+json.dumps(ipgeolocation["isp"])+', "asn":'+json.dumps(ipgeolocation["asn"]) +', "last_seen":'+json.dumps(ip_proxy_info["lastSeen"])+', "proxy_type":'+json.dumps(ip_proxy_info["proxyType"])+', "threat":'+json.dumps(ip_proxy_info["threat"])+', "is_proxy":'+json.dumps(ip_proxy_info["isProxy"])+'}}')
        except:
            return json.loads('{"ip_geolocation_info": {"error_occurred":'+json.dumps(ipgeolocation)+'}}')

        return ip_geolocation_info

    #Gets information on if the extracted IP address is using a proxy and if it is malicious (also provides the ASN and geolocation info)
    def get_ip_proxy_info(self): 
        config = configparser.ConfigParser()
        config.read('./config.txt')
        key = config['Ip2proxy']['API_KEY']
        try:
            response = requests.get('https://api.ip2proxy.com/?ip=' + self.ip + '&key=' + key + '&package=PX10').json()
        except Exception as error: 
            return json.dumps('{"lastSeen": '+'{0}\n'.format(error)+', "proxyType": "NA", "threat": "NA", "isProxy": "NA"}')

        return response

    #Translates the extracted IP address to a domain name (Reverse IP / IP Passive DNS lookup)
    def get_reverse_ip_info(self): 
        config = configparser.ConfigParser()
        config.read('./config.txt')
        key = config['FarsightSecurity']['API_KEY']
        try: 
            request = dnsdb.DNSDBAPI(api_key=key).inverse_lookup(_type='ip', value=self.ip)
            reverse_ip_info = dnsdb.dnsdb_results_to_json(request)

            if reverse_ip_info == '[]': 
                return json.loads('{"passive_dns_information": {"error_occurred": "No Passive DNS information found"}}')

            reverse_ip_info = json.loads('{"reverse_ip_information":'+ reverse_ip_info +'}')
        except:
            return json.loads('{"reverse_ip_information": {"error_occurred": '+json.dumps(reverse_ip_info)+'}}')

        return reverse_ip_info

    #Get the IPv4 or IPv6 indicators from the related AlienVault pulses of the given IPv4 or IPv6 address
    def get_related_ip_indicators(self): 
        ip_indicators = []
        try: 
            try: 
                indicator_report = self.avi.get_related_pulse_indicators(self.ip, 'IPv4')
            except: 
                indicator_report = self.avi.get_related_pulse_indicators(self.ip, 'IPv6')

            for i in range(0, len(indicator_report)): 
                ip_indicators.append({'pulse_id': indicator_report[i]['pulse_key'], 'indicator_id': indicator_report[i]['id'], 'indicator': indicator_report[i]['indicator'], 'type': indicator_report[i]['type'], 'created_date': indicator_report[i]['created']})

            ip_indicators = json.loads('{"related_indicators_of_ip_address":'+json.dumps(ip_indicators)+'}')
        except Exception as error:
            return json.loads('{"related_indicators_of_ip_address": {"error_occurred": '+json.dumps('{0}'.format(error))+'}}')

        return ip_indicators

    #Gets information about related pulses such as threat group for the given IPv4 or IPv6 address
    def get_related_ip_pulse_info(self): 
        try: 
            ip_pulse_info = []
            try: 
                pulse_report = self.avi.get_related_pulse_report(self.ip, 'IPv6')
            except: 
                pulse_report = self.avi.get_related_pulse_report(self.ip, 'IPv4')

            for k in range(0, len(pulse_report)): 
                ip_pulse_info.append({'Id': pulse_report[k]['id'], 'Name': pulse_report[k]['name'], 'Adversary': pulse_report[k]['adversary'], 'Attack IDs': pulse_report[k]['attack_ids'], 'Tags': pulse_report[k]['tags']})

            ip_pulse_info = json.loads('{"related_pulses_of_ip_address":'+json.dumps(ip_pulse_info)+'}')
        except Exception as error:
            return json.loads('{"related_pulses_of_ip_address": {"error_occurred": '+json.dumps('{0}'.format(error))+'}}')
            
        return ip_pulse_info

    #Gets IP address threat intelligence from grey noise such as if it is malicious and threat actor
    def get_grey_noise_info(self):
        try:
            grey_noise_info = self.gni.get_ip_intelligence(self.ip)
            grey_noise_info = json.loads('{"greynoise_threat_intelligence": {"ip":'+json.dumps(grey_noise_info['ip'])+', "noise":'+json.dumps(grey_noise_info['noise'])+', "rule_it_out":'+json.dumps(grey_noise_info['riot'])+', "classification":'+json.dumps(grey_noise_info['classification'])+', "threat_actor":'+json.dumps(grey_noise_info['name'])+', "last_seen":'+json.dumps(grey_noise_info['last_seen'])+', "link":'+json.dumps(grey_noise_info['link'])+'}}')
        except: 
            return json.loads('{"greynoise_threat_intelligence": {"error_occurred": '+json.dumps(grey_noise_info)+'}}')

        return grey_noise_info