import tldextract, csv

#For checking if extracted URLs, domains, IPs are whitelisted
class WhitelistAnalysis:
    #def __init__(self): 
        #self.url = url

    def check_domain_whitelist(self, url): 
        extract = tldextract.extract(url)
        
        length = len(extract)
        is_whitelisted_top_domains = False
        is_whitelisted_full_domain = False

        print(extract)

        #To get domain (E.g. google.com)
        top_domains = extract[length-2] + "." + extract[length-1]

        #To get subdomains as well as the tld and sld (E.g. docs.google.com)
        full_domain = extract[length-3] + "." + extract[length-2] + "." + extract[length-1]

        #Check if extracted domains and subdomains match a record on the majestic_million whitelist file
        with open('Whitelisting/majestic_million.csv', 'rt', encoding='utf-8') as f: 
            reader = csv.reader(f, delimiter=',')
            for row in reader: 
                for field in row:
                    if field == top_domains:
                        is_whitelisted_top_domains = True
                    elif field == full_domain:
                        is_whitelisted_full_domain = True
        
        return is_whitelisted_top_domains, is_whitelisted_full_domain, top_domains, full_domain

    #Removes unrelated and duplicate URLs that are extracted from procmemory from dynamic_urls
    def remove_unrelated_urls(self, dynamic_urls): 
        #Specifies URLs to be whitelisted
        unrelated_urls = ["http://www.chambersign.org", "http://crl.chambersign.org/chambersroot.crl"]
        
        dynamic_urls = set(dynamic_urls)

        for i in range(0, len(unrelated_urls)): 
            dynamic_urls.discard(unrelated_urls[i])

        return dynamic_urls