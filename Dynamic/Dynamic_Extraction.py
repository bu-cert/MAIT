import requests, time, ast, re, configparser, json, os, r2pipe
#For extraction of URLs from an executable using the Cuckoo sandbox
class DynamicAnalysis: 
    def __init__(self):#, file_path):
        #self.file_path = file_path
        
        config = configparser.ConfigParser()
        config.read('./config.txt')
        
        self.BASE_URL = config['cuckoo']['BASEDIR']
        self.HEADERS = {"Authorization": "Bearer 5oJkH42IbX5cK42-eXQSqw"}
        self.options = {"options": ["procmemdump=yes", "memory=yes"]}

    def submit_sample(self): 
        CREATE_FILE_REQUEST = self.BASE_URL + "tasks/create/file"
        with open(self.file_path, "rb") as sample:
            files = {"file": ("malware to be analysed", sample)}
            r = requests.post(CREATE_FILE_REQUEST, headers=self.HEADERS, files=files, data=self.options)
        # Add code to error checking for r.status_code. 
        #status_code = r.status_code
        #if r.status_code == 200: else


        task_id = str(r.json()["task_id"])

        # Add code for error checking if task_id is None.

        return task_id#, status_code
    
    #Function for handling if task analysis and reporting is done
    def get_task_status(self, task_id):
        task_done = False

        while True: 
            time.sleep(20)
            TASK_STATUS_REQUEST = self.BASE_URL + "tasks/view/" + task_id
            task_info = requests.get(TASK_STATUS_REQUEST, headers=self.HEADERS, data=self.options)
            task_status = str(task_info.json()["task"]["status"])
            timeString = time.ctime()
            print(timeString[11:(len(timeString)-5)] + " Task status: " + task_status)
            if task_status == "reported": 
                break
        
        task_done = True
        return task_done


    def get_strings(self, dump):
        print("retrieving headers from the malware "+dump)
        r2p = r2pipe.open(dump)
        strings = r2p.cmd("aaa;izz")
        return strings

    def get_urls(self, dump): 
        strings = self.get_strings(dump)
        print(strings)
        regex_url = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
        urls = re.findall(regex_url,strings)
        urls = list(set(urls))
        return urls

    def get_domains(self, dump): 
        strings = self.get_strings(dump)
        print(strings)
        regex_url = r"\b(?:(?:[a-z0-9\-]{2,}\.)+(?:cancerresearch|international|construction|versicherung|accountants|barclaycard|blackfriday|contractors|engineering|enterprises|investments|motorcycles|photography|productions|williamhill|associates|bnpparibas|consulting|creditcard|cuisinella|eurovision|foundation|healthcare|immobilien|industries|management|properties|republican|restaurant|technology|university|vlaanderen|allfinanz|amsterdam|aquarelle|bloomberg|christmas|community|directory|education|equipment|financial|furniture|institute|marketing|melbourne|solutions|vacations|airforce|attorney|barclays|bargains|boutique|brussels|budapest|builders|business|capetown|catering|cleaning|clothing|computer|delivery|democrat|diamonds|discount|engineer|everbank|exchange|feedback|firmdale|flsmidth|graphics|holdings|lighting|marriott|memorial|mortgage|partners|pharmacy|pictures|plumbing|property|saarland|services|software|supplies|training|ventures|yokohama|abogado|academy|android|auction|capital|caravan|careers|cartier|channel|college|cologne|company|cooking|country|cricket|cruises|dentist|digital|domains|exposed|fashion|finance|fishing|fitness|flights|florist|flowers|forsale|frogans|gallery|guitars|hamburg|hangout|holiday|hosting|kitchen|lacaixa|latrobe|limited|network|neustar|okinawa|organic|realtor|recipes|rentals|reviews|samsung|schmidt|schwarz|science|shiksha|shriram|singles|spiegel|support|surgery|systems|temasek|toshiba|website|wedding|whoswho|youtube|zuerich|active|agency|alsace|bayern|berlin|camera|career|center|chrome|church|claims|clinic|coffee|condos|credit|dating|degree|dental|design|direct|doosan|durban|emerck|energy|estate|events|expert|futbol|garden|global|google|gratis|hermes|hiphop|insure|joburg|juegos|kaufen|lawyer|london|luxury|madrid|maison|market|monash|mormon|moscow|museum|nagoya|otsuka|photos|physio|quebec|reisen|repair|report|ryukyu|schule|social|supply|suzuki|sydney|taipei|tattoo|tennis|tienda|travel|viajes|villas|vision|voting|voyage|webcam|yachts|yandex|actor|adult|archi|audio|autos|bingo|black|build|canon|cards|cheap|citic|click|coach|codes|cymru|dabur|dance|deals|email|gifts|gives|glass|globo|gmail|green|gripe|guide|homes|horse|house|irish|jetzt|koeln|kyoto|lease|legal|loans|lotte|lotto|mango|media|miami|money|nexus|ninja|osaka|paris|parts|party|photo|pizza|place|poker|praxi|press|rehab|reise|rocks|rodeo|shoes|solar|space|style|tatar|tires|tirol|today|tokyo|tools|trade|trust|vegas|video|vodka|wales|watch|works|world|aero|army|arpa|asia|band|bank|beer|best|bike|blue|buzz|camp|care|casa|cash|cern|chat|city|club|cool|coop|dclk|desi|diet|docs|docx|dvag|fail|farm|fish|fund|gbiz|gent|ggee|gift|goog|guru|haus|help|here|host|html|immo|info|jobs|kddi|kiwi|kred|land|lgbt|lidl|life|limo|link|ltda|luxe|meet|meme|menu|mini|mobi|moda|name|navy|pics|pink|pohl|porn|post|prod|prof|qpon|reit|rest|rich|rsvp|ruhr|sale|sarl|scot|sexy|sohu|surf|tiff|tips|town|toys|vote|voto|wang|wien|wiki|work|xlsx|yoga|zone|axa|bar|bid|bin|bio|biz|bmw|boo|bzh|cal|cat|ceo|cgi|com|crl|crs|crt|dad|day|dev|dnp|doc|eat|edu|esq|eus|exe|fit|fly|foo|frl|gal|gif|gle|gmo|gmx|gop|gov|hiv|how|htm|ibm|ifm|img|ing|ink|int|iwc|jcb|jpg|kim|krd|lat|lds|mil|moe|mov|mp|net|new|ngo|nhk|nra|nrw|ntt|nyc|one|ong|onl|ooo|org|ovh|png|pro|pub|red|ren|rio|rip|sca|scb|sew|sky|soy|tax|tel|top|tui|txt|uno|uol|vet|wed|wme|wtc|wtf|xls|xxx|xyz|zip|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw))\b"
        urls = re.findall(regex_url,strings)
        urls = list(set(urls))
        return urls

    def get_procmemory_urls(self, task_id): 
        urls = []
        domains = []
        for filename in os.listdir('/home/e-ews/.cuckoo/storage/analyses/'+str(task_id)+'/memory/'):
            urls.append(self.get_urls('/home/e-ews/.cuckoo/storage/analyses/'+str(task_id)+'/memory/'+filename))
            domains.append(self.get_domains('/home/e-ews/.cuckoo/storage/analyses/'+str(task_id)+'/memory/'+filename))
        #urls = self.remove_unrelated_urls(urls)
        return (urls, domains)

    def get_netscan_ips(self, task_id): 
        REPORT_REQUEST = self.BASE_URL + "tasks/report/" +  str(task_id)
        report = requests.get(REPORT_REQUEST, headers=self.HEADERS, data=self.options)

        ips = []

        try: 
            netscan_length = len(report.json()["memory"]["netscan"]["data"])
        except: 
            return ips

        for i in range(0, netscan_length): 
            ip = report.json()["memory"]["netscan"]["data"][i]["remote_address"]
            ips.append(ip)
        
        ips = self.remove_unrelated_ips(ips)

        return ips

    #Removes unrelated and duplicate URLs that are extracted from procmemory from dynamic_urls and/or from strings
    def remove_unrelated_urls(self, dynamic_urls): 
        #Specifies URLs to be whitelisted
        unrelated_urls = ["http://www.quovadisglobal.com", "http://crl.comodo.net/TrustedCertificateServices.crl", "http://users.ocsp.d-trust.net03", "http://crl.ssc.lt/root-b/cacrl.crl", "http://crl.securetrust.com/STCA.crl", "http://crl.securetrust.com/SGCA.crl", "http://acraiz.icpbrasil.gov.br/DPCacraiz.pdf0=", "http://www.ssc.lt/CPS3", "http://www.informatik.admin.ch/PKI/links/CPS_2_16_756_1_17_3_1_0.pdf0", "http://www.certificadodigital.com.br/repositorio/serasaca/crl/SerasaCAII.crl", "http://www.digsigtrust.com/DST_TRUST_CPS_v990701.html", "http://www.microsoft.com/pki/certs/TrustListPCA.crt0", "https://www.certification.tn/cgi-bin/pub/crl/cacrl.crl", "http://www.pkioverheid.nl/policies/root-policy0", "http://cps.chambersign.org/cps/chambersroot.html", "http://www.e-szigno.hu/SZSZ/0", "http://www.entrust.net/CRL/Client1.crl", "http://crl.chambersign.org/publicnotaryroot.crl", "http://crl.comodo.net/AAACertificateServices.crl", "http://www.certplus.com/CRL/class3.crl", "http://logo.verisign.com/vslogo.gif0", "http://www.acabogacia.org/doc0", "http://www.disig.sk/ca/crl/ca_disig.crl", "https://www.catcert.net/verarrel", "http://www.sk.ee/cps/0", "http://www.quovadis.bm0", "https://www.catcert.net/verarrel05", "http://www.certificadodigital.com.br/repositorio/serasaca/crl/SerasaCAI.crl", "http://crl.chambersign.org/chambersroot.crl", "http://www.certificadodigital.com.br/repositorio/serasaca/crl/SerasaCAIII.crl", "http://crl.globalsign.net/root-r2.crl", "http://certificates.starfieldtech.com/repository/1604", "http://www.d-trust.net0", "http://pki-root.ecertpki.cl/CertEnroll/E-CERT%20ROOT%20CA.crl", "http://crl.ssc.lt/root-a/cacrl.crl", "http://crl.usertrust.com/UTN-DATACorpSGC.crl", "http://www.certicamara.com/certicamaraca.crl", "http://www.d-trust.net/crl/d-trust_root_class_2_ca_2007.crl", "http://crl.usertrust.com/UTN-USERFirst-Object.crl", "http://www.post.trust.ie/reposit/cps.html", "http://www.d-trust.net/crl/d-trust_qualified_root_ca_1_2007_pn.crl", "http://www2.public-trust.com/crl/ct/ctroot.crl", "http://www.certicamara.com", "http://www.pki.admin.ch/policy/CPS_2_16_756_1_17_3_21_1.pdf", "http://fedir.comsign.co.il/cacert/ComSignAdvancedSecurityCA.crt", "http://www.comsign.co.il/CPS", "http://crl.usertrust.com/UTN-USERFirst-NetworkApplications.crl", "http://www.microsoft.com/pki/crl/products/TrustListPCA.crl", "http://acraiz.icpbrasil.gov.br/LCRacraiz.crl", "http://www.signatur.rtr.at/de/directory/cps.html", "http://www.globaltrust.info", "http://ca.sia.it/secsrv/repository/CRL.der", "http://support.microsoft.com/kb/9311250", "http://crl.usertrust.com/UTN-USERFirst-ClientAuthenticationandEmail.crl", "https://secure.a-cert.at/cgi-bin/a-cert-advanced.cgi", "http://www.certplus.com/CRL/class3TS.crl", "http://crl.usertrust.com/UTN-USERFirst-Hardware.crl", "http://crl.xrampsecurity.com/XGCA.crl", "http://repository.infonotary.com/cps/qcps.html", "http://www.firmaprofesional.com", "http://www.disig.sk/ca", "http://www.acabogacia.org", "http://www.usertrust.com1", "http://www.e-certchile.cl/html/productos/download/CPSv1.7.pdf", "http://www.pki.gva.es/CPS", "http://www.certicamara.com/dpc/", "http://www.e-me.lv/repository", "http://www.dnie.es/dpc", "http://fedir.comsign.co.il/crl/ComSignCA.crl", "http://www.wellsfargo.com/certpolicy", "http://repository.swisssign.com/", "https://www.certification.tn/cgi-bin/pub/crl/cacrl.crl", "http://crl.ssc.lt/root-c/cacrl.crl", "http://fedir.comsign.co.il/crl/ComSignAdvancedSecurityCA.crl", "https://www.netlock.hu/docs/", "http://www.quovadisglobal.com/CPS", "http://crl.pki.wellsfargo.com/wsprca.crl", "http://www.a-cert.at", "http://www.e-szigno.hu/RootCA.crt", "http://www.chambersign.org", "http://qual.ocsp.d-trust.net", "http://crl.netsolssl.com/NetworkSolutionsCertificateAuthority.crl", "http://www.trustdst.com/certificates/policy/ACES-index.html", "https://rca.e-szigno.hu/ocsp", "https://ca.sia.it/seccli/repository/CPS", "http://www.ancert.com/CPS", "https://ca.sia.it/secsrv/repository/CPS", "http://www.certifikat.dk/repository", "http://www.entrust.net/CRL/net1.crl", "http://www.trustcenter.de/guidelines", "http://cps.chambersign.org/cps/publicnotaryroot.html", "http://www.trustcenter.de/crl/v2/tc_class_2_ca_II.crl", "https://ocsp.quovadisoffshore.com", "http://www.e-trust.be/CPS/QNcerts", "http://www.certplus.com/CRL/class1.crl", "http://ocsp.infonotary.com/responder.cgi", "http://ca.disig.sk/ca/crl/ca_disig.crl", "http://www.registradores.org/scr/normativa/cp_f2.htm", "http://crl.oces.certifikat.dk/oces.crl", "http://ca.sia.it/seccli/repository/CRL.der", "http://www.signatur.rtr.at/current.crl", "http://www.certplus.com/CRL/class2.crl", "http://www.a-cert.at/certificate-policy.html", "http://www.crc.bg", "http://crl.chambersign.org/chambersignroot.crl", "http://www.certplus.com/CRL/class3P.crl", "https://www.netlock.net/docs", "http://fedir.comsign.co.il/crl/ComSignSecuredCA.crl", "http://www.microsoft.com/pki/certs/tspca.crt", "http://ocsp.pki.gva.es", "http://www.rootca.or.kr/rca/cps.html", "http://crl.comodoca.com/TrustedCertificateServices.crl", "http://www.echoworx.com/ca/root2/cps.pdf", "http://www.trustcenter.de/crl/v2/tc_class_3_ca_II.crl", "http://www.valicert.com/", "http://crl.comodoca.com/AAACertificateServices.crl", "http://www.sk.ee/juur/crl/", "http://www.usertrust.com", "http://cps.chambersign.org/cps/chambersignroot.html", "http://crl.comodoca.com/COMODOCertificationAuthority.crl", "http://test.com", "http://ns.adobe.com", "http://www.microsoft.com", "http://www.passport.com", "https://r20swj13mr.microsoft.com/ieblocklist/v1/urlblockindex.bin", "http://purl.org", "https://iecvlist.microsoft.com"]
        
        dynamic_urls = set(dynamic_urls)

        for i in range(0, len(unrelated_urls)): 
            dynamic_urls.discard(unrelated_urls[i])

        return list(dynamic_urls)

    #Removes unrelated and duplicate IP addresses that are extracted using the Volatility netscan plugin and/or from strings
    def remove_unrelated_ips(self, ip_addresses): 
        #Specifies IP addresses to be whitelisted
        unrelated_ips = [None, "*", "::", "0.0.0.0", "192.168.56.1", "127.0.0.1", "192.168.56.255", "56.139.111.3", "56.230.162.3", "38cb:8a01:80fa:ffff:38cb:8a01:80fa:ffff", "104.34.199.1", "38e6:a203:80fa:ffff:38e6:a203:80fa:ffff"]

        ip_addresses = set(ip_addresses)

        for i in range(0, len(unrelated_ips)): 
            ip_addresses.discard(unrelated_ips[i])

        return list(ip_addresses)

    def get_dynamic_indicators(self, task_id): 
        try: 
            #task_id = self.submit_sample()

            #if self.get_task_status(task_id = task_id) == True: 
            urls, domains = self.get_procmemory_urls(task_id = task_id)
            dynamic_urls = json.dumps(urls)
            dynamic_domains = json.dumps(domains)
            dynamic_ips = json.dumps(self.get_netscan_ips(task_id = task_id))

            dynamic_indicators = json.loads('{"dynamic_indicators": {"urls":'+json.dumps(dynamic_urls)+', "domains":'+json.dumps(dynamic_domains)+',"ip_addresses":'+json.dumps(dynamic_ips)+'}}')
        except Exception as error: 
            return json.loads(r'"dynamic_indicators": {"error_occurred":'+json.dumps('{0}\n'.format(error))+'}')

        return dynamic_indicators



        

