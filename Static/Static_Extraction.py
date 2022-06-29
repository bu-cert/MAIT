import r2pipe, re, json

#For extracting URLs, domains and IP addresses from an executable using radare2
class StaticAnalysis:
    def __init__(self, file_path): 
        self.file_path = file_path

    def get_strings(self): 
        r = r2pipe.open(self.file_path)
        strings = r.cmd('aa;izz')

        return strings 

    def get_ipv4_addresses(self): 
        strings = self.get_strings()

        #Regex reference: Available at: https://www.geeksforgeeks.org/how-to-validate-an-ip-address-using-regex/, accessed 14th April 2021
        regex_ipv4 = r"\b(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b"
        ipv4_addresses = re.findall(regex_ipv4,strings)

        ipv4_addresses = list(set(ipv4_addresses))

        return ipv4_addresses

    def get_ipv6_addresses(self): 
        strings = self.get_strings()

        #Regex reference: Available at: https://gist.github.com/syzdek/6086792, accessed 31st March 2021
        regex_ipv6 = r"(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(:0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
        ipv6_addresses = re.findall(regex_ipv6,strings)

        ipv6_addresses = list(set(ipv6_addresses))

        return ipv6_addresses

    def get_urls(self): 
        strings = self.get_strings()
        
        regex_url = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
        urls = re.findall(regex_url,strings)

        urls = list(set(urls))

        return urls

    def get_domains(self): 
        strings = self.get_strings()

        regex_domain = r"\b(?:(?:[a-z0-9\-]{2,}\.)+(?:cancerresearch|international|construction|versicherung|accountants|barclaycard|blackfriday|contractors|engineering|enterprises|investments|motorcycles|photography|productions|williamhill|associates|bnpparibas|consulting|creditcard|cuisinella|eurovision|foundation|healthcare|immobilien|industries|management|properties|republican|restaurant|technology|university|vlaanderen|allfinanz|amsterdam|aquarelle|bloomberg|christmas|community|directory|education|equipment|financial|furniture|institute|marketing|melbourne|solutions|vacations|airforce|attorney|barclays|bargains|boutique|brussels|budapest|builders|business|capetown|catering|cleaning|clothing|computer|delivery|democrat|diamonds|discount|engineer|everbank|exchange|feedback|firmdale|flsmidth|graphics|holdings|lighting|marriott|memorial|mortgage|partners|pharmacy|pictures|plumbing|property|saarland|services|software|supplies|training|ventures|yokohama|abogado|academy|android|auction|capital|caravan|careers|cartier|channel|college|cologne|company|cooking|country|cricket|cruises|dentist|digital|domains|exposed|fashion|finance|fishing|fitness|flights|florist|flowers|forsale|frogans|gallery|guitars|hamburg|hangout|holiday|hosting|kitchen|lacaixa|latrobe|limited|network|neustar|okinawa|organic|realtor|recipes|rentals|reviews|samsung|schmidt|schwarz|science|shiksha|shriram|singles|spiegel|support|surgery|systems|temasek|toshiba|website|wedding|whoswho|youtube|zuerich|active|agency|alsace|bayern|berlin|camera|career|center|chrome|church|claims|clinic|coffee|condos|credit|dating|degree|dental|design|direct|doosan|durban|emerck|energy|estate|events|expert|futbol|garden|global|google|gratis|hermes|hiphop|insure|joburg|juegos|kaufen|lawyer|london|luxury|madrid|maison|market|monash|mormon|moscow|museum|nagoya|otsuka|photos|physio|quebec|reisen|repair|report|ryukyu|schule|social|supply|suzuki|sydney|taipei|tattoo|tennis|tienda|travel|viajes|villas|vision|voting|voyage|webcam|yachts|yandex|actor|adult|archi|audio|autos|bingo|black|build|canon|cards|cheap|citic|click|coach|codes|cymru|dabur|dance|deals|email|gifts|gives|glass|globo|gmail|green|gripe|guide|homes|horse|house|irish|jetzt|koeln|kyoto|lease|legal|loans|lotte|lotto|mango|media|miami|money|nexus|ninja|osaka|paris|parts|party|photo|pizza|place|poker|praxi|press|rehab|reise|rocks|rodeo|shoes|solar|space|style|tatar|tires|tirol|today|tokyo|tools|trade|trust|vegas|video|vodka|wales|watch|works|world|aero|army|arpa|asia|band|bank|beer|best|bike|blue|buzz|camp|care|casa|cash|cern|chat|city|club|cool|coop|dclk|desi|diet|docs|docx|dvag|fail|farm|fish|fund|gbiz|gent|ggee|gift|goog|guru|haus|help|here|host|html|immo|info|jobs|kddi|kiwi|kred|land|lgbt|lidl|life|limo|link|ltda|luxe|meet|meme|menu|mini|mobi|moda|name|navy|pics|pink|pohl|porn|post|prod|prof|qpon|reit|rest|rich|rsvp|ruhr|sale|sarl|scot|sexy|sohu|surf|tiff|tips|town|toys|vote|voto|wang|wien|wiki|work|xlsx|yoga|zone|axa|bar|bid|bin|bio|biz|bmw|boo|bzh|cal|cat|ceo|cgi|com|crl|crs|crt|dad|day|dev|dnp|doc|eat|edu|esq|eus|exe|fit|fly|foo|frl|gal|gif|gle|gmo|gmx|gop|gov|hiv|how|htm|ibm|ifm|img|ing|ink|int|iwc|jcb|jpg|kim|krd|lat|lds|mil|moe|mov|net|new|ngo|nhk|nra|nrw|ntt|nyc|one|ong|onl|ooo|org|ovh|png|pro|pub|red|ren|rio|rip|sca|scb|sew|sky|soy|tax|tel|top|tui|txt|uno|uol|vet|wed|wme|wtc|wtf|xls|xxx|xyz|zip|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw))\b"
        domains = re.findall(regex_domain,strings)

        domains = list(set(domains))

        return domains

    def get_static_indicators(self): 
        try: 
            static_indicators = '"static_indicators": {"urls":'+self.get_urls()+', "domains":'+self.get_domains()+', "ipv4_addresses":'+self.get_ipv4_addresses()+', "ipv6_addresses":'+self.get_ipv6_addresses()+'}'#json.loads()
        except Exception as error: 
            return '"static_indicators": {"error_occurred":'+json.dumps('{0}\n'.format(error))+'}'
            
        return static_indicators