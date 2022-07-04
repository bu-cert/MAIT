from distutils.log import debug
import flask
from Static import analysis 
#from Static import functioncall
from Dynamic import cuckoo_interface
from CTI import alienvault_interface
from CTI import virustotal_interface
from CTI import abusech_interface
from CTI import apt_intelligence
from CTI import chrono_intelligence
from CTI import URLCTI, IPCTI
from CTI import create_nav
from Quarantine import quarantine
from Static import Static_Extraction
from Dynamic import Dynamic_Extraction
from Whitelisting import URL_Whitelist_Analysis
from Quarantine import quarantine
import json
import time
import os
import hashlib
import configparser
from flask import Flask, request, abort, jsonify, send_from_directory
import pymongo
import requests
from requests.auth import HTTPBasicAuth
import pprint
from flask_cors import CORS
from waitress import serve
UPLOAD_DIRECTORY = "./Uploads"

DISPOSAL_DIRECTORY = "./Disposal"

if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)


app = flask.Flask(__name__)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

app.config["DEBUG"] = True
@app.route('/api/v1/files', methods=['GET'])
def list_files():
    """Endpoint to list files on the server."""
    files = []
    for filename in os.listdir(UPLOAD_DIRECTORY):
        path = os.path.join(UPLOAD_DIRECTORY, filename)
        if os.path.isfile(path):
            files.append(filename)
    response = jsonify(files)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response


@app.route('/api/v1/disposal', methods=['GET'])
def list_qfiles():
    """Endpoint to list files on the server."""
    files = []
    for filename in os.listdir(DISPOSAL_DIRECTORY):
        path = os.path.join(DISPOSAL_DIRECTORY, filename)
        if os.path.isfile(path):
            files.append(filename)
    response = jsonify(files)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

@app.route('/api/v1/quarantine/<path:path>/', methods=['GET'])
def quarantine_file(path):
    path = UPLOAD_DIRECTORY+ '/'+path
    s = analysis.Static()
    urlhash = s.hash_256(path)
    quarantine.inject_new_section(path, urlhash)
    quarantine.encrypt_file('infected_by_MAIT'.encode("utf8"), in_filename='./Disposal/'+urlhash+'.quarantine', out_filename='./Disposal/'+urlhash+'.enc.quarantine')
    os.remove(path)
    os.remove('./Disposal/'+urlhash+'.quarantine')     
    response = jsonify(success="{ok}")
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response


@app.route("/api/v1/fileupload/", methods=["POST"])
def post_file():
    """Upload a file."""
    print(str(request.files))
    files = request.files['upload_file']
    filename = files.filename
    if files:
        files.save(os.path.join(UPLOAD_DIRECTORY, filename))
        file_size = os.path.getsize(os.path.join(UPLOAD_DIRECTORY, filename))
        response=jsonify(name=filename, size=file_size)
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response


@app.route("/api/v1/files/<path:path>")
def get_file(path):
    """Download a file."""
    return send_from_directory(UPLOAD_DIRECTORY, path, as_attachment=True)


@app.route('/api/v1/static/<path:path>/analysis/', methods=['GET'])
def static_get_analysis(path):
    """Return the headers from static analysis"""
    path = UPLOAD_DIRECTORY+ '/'+path
    s = analysis.Static(path)
    summary = s.get_headers(path)
    urlhash = s.hash_256(path)
    imphash = s.get_imphash(path)
    impfuzzy = s.get_impfuzzy(path)
    lib =  s.get_libraries(path)
    net =  s.get_network_ops(path)
    sec =  s.get_entropy(path)
    strings =  s.get_strings(path)
    response = jsonify(summary = summary, sha256 = urlhash, imphash = imphash, impfuzzy = impfuzzy, libraries = lib, network = net, sections = sec, strings =strings)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

@app.route('/api/v1/dynamic/<path:path>/analysis/', methods=['GET'])
def dynamic_get_report(path):
    d = cuckoo_interface.Dynamic()
    da = Dynamic_Extraction.DynamicAnalysis()###
    path = UPLOAD_DIRECTORY+ '/'+path
    task_id = d.submit_file(path)
    while d.is_finished(task_id) == False:
    	time.sleep(30)
    
    if d.is_finished(task_id):
        report = d.get_report(task_id)
        summary = d.get_summary(report)
        apicalls = d.get_apicalls(report)
        ttps = d.get_ttps(report)

        #dynamic_iocs = da.get_dynamic_indicators(task_id)###

        network = d.get_network(report)
        dropped = d.get_dropped_files(report)
        signatures = d.get_signatures(report)

        ttp_report_file = open('ttps.json', 'w') #TODO: Test this - for adding dynamic cuckoo ttps to alienvault ttps for attack mapping 
        ttp_report_file.write(json.dumps({'ttps': ttps})) #
        ttp_report_file.close() #

        #response = jsonify(summary = summary, apicalls = apicalls, ttps = ttps, network = network, drop=dropped, signatures=signatures, dynamic_iocs=dynamic_iocs)
        response = jsonify(summary = summary, apicalls = apicalls, ttps = ttps, network = network, drop=dropped, signatures=signatures)
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

#APT campaign connection 
@app.route('/api/v1/cti/<path:path>/analysis/', methods=['GET'])
def cti_get_report(path):
    s = analysis.Static()
    apt_intel = apt_intelligence.APT_Intelligence()
    chrono_intel = chrono_intelligence.Chrono_Intelligence()


    path = UPLOAD_DIRECTORY+ '/'+path
    urlhash = s.hash_256(path)
    
    attrb = apt_intel.find_apt_name(urlhash)
    ttps = apt_intel.AlienVault_TTPs(urlhash)
    tags, intel = apt_intel.malwarebazaar_tags_intel(urlhash)
    chronos1 = chrono_intel.malware_first_seen(urlhash)
    chronos2 = chrono_intel.virustotal_dates(urlhash)
    response = jsonify(attribution = attrb, ttps = ttps, tags = tags, intel = intel, first_seen = chronos1, vt_dates = chronos2)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response
    
    
@app.route('/api/v1/cti/<path:path>/hashanalysis/', methods=['GET'])
def cti_get_hashreport(path):
	apt_intel = apt_intelligence.APT_Intelligence()
	chrono_intel = chrono_intelligence.Chrono_Intelligence()
	attrb = apt_intel.find_apt_name(path)    
	ttps = apt_intel.AlienVault_TTPs(path)
	tags, intel = apt_intel.malwarebazaar_tags_intel(path)
	chronos1 = chrono_intel.malware_first_seen(path)
	chronos2 = chrono_intel.virustotal_dates(path)
	response = jsonify(attribution = attrb, ttps = ttps, tags = tags, intel = intel, first_seen = chronos1, vt_dates = chronos2)
	response.headers.add('Access-Control-Allow-Origin', '*')
	return response

@app.route('/api/v1/attacknav/<path:path>/', methods=['GET'])
def cti_get_mitre_mapping(path):
    nav = create_nav.Create_Nav()
    s = analysis.Static()
    path = UPLOAD_DIRECTORY+ '/'+path
    urlhash = s.hash_256(path)
    #urlhash = 'c874dd4a471fb101f8d019efbcf5b849d4575c36b479aea3d0ab54ad8ad6d164'
    f = open('ticket_template.json')
    template = json.loads(f.read())
    f.close()

    #TODO: Check this works - gets versions from config file 
    config = configparser.ConfigParser()
    config.read('./config.txt')
    template['versions']['layer'] = config['MitreAtt&ck']['attack_layer_version']
    template['versions']['attack'] = config['MitreAtt&ck']['attack_version']
    template['versions']['navigator'] = config['MitreAtt&ck']['attack_navigator_version']

    cuckoo_ttps_file = open('ttps.json') #TODO: Need to check ttp format in comparison to AlienVault first, maybe do json.loads(file.read)? 
    cuckoo_ttps = nav.get_cuckoo_ttps(json.loads(cuckoo_ttps_file.read()))
    cuckoo_ttps_file.close() #    

    lst = nav.AlienVault_TTPs(urlhash) + cuckoo_ttps

    #retrieve and update
    for i in lst:
        print(i)
        template['techniques'].append(i)
    response = jsonify(template)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response


@app.route('/api/v1/urlipintelligence/<path:path>/ioc/', methods=['GET'])
def cti_get_url_ip_iocs(path):
    path = UPLOAD_DIRECTORY+ '/'+path
    sa = Static_Extraction.StaticAnalysis(file_path = path)
    da = Dynamic_Extraction.DynamicAnalysis(file_path = path)
    extracted_iocs_report = json.loads('{"extracted_indicators":{'+sa.get_static_indicators()+', '+da.get_dynamic_indicators()+'}}')
    response = extracted_iocs_report
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

#URL campaign connection 
@app.route('/api/v1/urlcti/<path:path>/analysis/', methods=['GET'])
def cti_url_report(path):
    ucti = URLCTI.URL_CTI(path)
    try: 
        url_report = ucti.get_virustotal_score()
    except: 
        ucti.scan_url()
        print("No existing report found on VirusTotal, initiating scan now... ")
        time.sleep(20)
        url_report = ucti.get_virustotal_score()

    subdomains = ucti.get_subdomains()
    ip_resolutions = ucti.get_domain_ip_resolutions()
    whois_info = ucti.get_domain_whois()
    related_malicious_files = ucti.get_related_malicious_files()
    related_malicious_urls = ucti.get_related_malicious_urls()
    vt_historical_ssl = ucti.get_vt_historical_ssl_certs()
    crtsh_historical_ssl = ucti.get_crtsh_historical_ssl_certs()
    dns_info = ucti.get_dns_info()
    ssl_config_info = ucti.get_ssl_config_info()
    alerts = ucti.get_alienvault_alerts()
    pulse = ucti.get_related_url_pulse_info()
    url_indicators = ucti.get_related_url_indicators()
    domain_pulse_info = ucti.get_related_domain_pulse_info()
    domain_indicators = ucti.get_related_domain_indicators()
    response = jsonify(url_report = url_report, subdomains = subdomains, ip_resolutions = ip_resolutions,
                    whois_info = whois_info, related_malicious_files = related_malicious_files, related_malicious_urls = related_malicious_urls,
                    vt_historical_ssl = vt_historical_ssl, crtsh_historical_ssl = crtsh_historical_ssl,dns_info = dns_info, ssl_config_info = ssl_config_info
                    ,  alerts = alerts, pulse = pulse,url_indicators =url_indicators, domain_pulse_info = domain_pulse_info, domain_indicators= domain_indicators ) 
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response


#IP campaign connection 

@app.route('/api/v1/ipcti/<path:path>/analysis/', methods=['GET'])
def cti_ip_report(path):
    ipcti = IPCTI.IP_CTI(path)
    ipscore = ipcti.get_virustotal_score()
    related_malicious_files = ipcti.get_related_malicious_files()
    related_malicious_urls = ipcti.get_related_malicious_urls()

    hostnames = ipcti.get_hostname_resolutions()
    whois = ipcti.get_ip_whois()
    ssl_certs = ipcti.get_historical_ssl_certs()
    geolocation = ipcti.get_ip_geolocation()
    greynoise_cti = ipcti.get_grey_noise_info()
    related_pulse = ipcti.get_related_ip_pulse_info()
    related_indicators = ipcti.get_related_ip_indicators()#json.loads('{"wibble": {"na": "na"}}')
    response = jsonify( ipscore = ipscore, related_malicious_files = related_malicious_files, 
                        related_malicious_urls = related_malicious_urls, hostnames = hostnames, whois = whois,
                        ssl_certs = ssl_certs, geolocation = geolocation, 
                        greynoise_cti = greynoise_cti, related_pulse = related_pulse, related_indicators = related_indicators)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

@app.route('/api/v1/submitews/', methods=['POST'])
def submit_to_ews():

    config = configparser.ConfigParser()
    config.read('./config.txt')
    ewsdir = config['EWS']['EWSDIR']
    user = config['EWS']['username']
    password = config['EWS']['password']

    f = open('ticket_template.json')
    template = json.loads(f.read())
    f.close()    

    data = json.loads(request.data)
    for i in data:
        if i['name'] == 'filename':
            path = i['value']
        elif i['name'] == 'TLP':
            tlp = i['value']
        elif i['name'] == 'Priority':
            pri = i['value']
        elif i['name'] == 'title':
            title = i['value']
        elif i['name'] == 'Description':
            desc = i['value']
    print(path, tlp, pri, title, desc)
    template['title'] = title
    template['description'] = desc
    template['distribution'] = tlp
    print(template['ticketAttributes'])
    template['ticketAttributes'][1]['value']['values'] = [str(pri)]

    path = UPLOAD_DIRECTORY+ '/'+path
    
    s = analysis.Static()
    summary = s.get_headers(path)
    urlhash = s.hash_256(path)
    imphash = s.get_imphash(path)
    impfuzzy = s.get_impfuzzy(path)
    lib =  s.get_libraries(path)
    net =  s.get_network_ops(path)
    sec =  s.get_entropy(path)
    strings =  s.get_strings(path)
    static = jsonify(summary = summary, sha256 = urlhash, imphash = imphash, impfuzzy = impfuzzy, libraries = lib, network = net, sections = sec, strings =strings)
    to_save = pprint.pformat(static.json)
    f = open('static.json', 'w')
    print(to_save, file=f)
    f.close()


    apt_intel = apt_intelligence.APT_Intelligence()
    chrono_intel = chrono_intelligence.Chrono_Intelligence()

    attrb = apt_intel.find_apt_name(urlhash)
    ttps = apt_intel.AlienVault_TTPs(urlhash)
    tags, intel = apt_intel.malwarebazaar_tags_intel(urlhash)
    chronos1 = chrono_intel.malware_first_seen(urlhash)
    chronos2 = chrono_intel.virustotal_dates(urlhash)
    cti = jsonify(attribution = attrb, ttps = ttps, tags = tags, intel = intel, first_seen = chronos1, vt_dates = chronos2)

    to_save_cti = pprint.pformat(cti.json)
    f = open('cti.json', 'w')
    print(to_save_cti, file=f)
    f.close()

    d = cuckoo_interface.Dynamic()
    task_id = d.submit_file(path)
    while d.is_finished(task_id) == False:
        time.sleep(2)
    if d.is_finished(task_id):
        report = d.get_report(task_id)
        summary = d.get_summary(report)
        apicalls = d.get_apicalls(report)
        ttps = d.get_ttps(report)
        network = d.get_network(report)
        dropped = d.get_dropped_files(report)
        signatures = d.get_signatures(report)
        dynamic = jsonify(summary = summary, apicalls = apicalls, ttps = ttps, network = network, drop=dropped, signatures=signatures)
    
    to_save_dynamic = pprint.pformat(dynamic.json)
    f = open('dynamic.json', 'w')
    print(to_save_dynamic, file=f)
    f.close()
    
    #Create a ticket and attach the report
    url = ewsdir+"api/sdk/cybertickets/"
    headers = {'Content-Type': 'application/json'}
    response = requests.request('POST', url, headers = headers, data = json.dumps(template), auth=HTTPBasicAuth(user, password))
    print(response.text.encode('utf-8'))
    ticket_id = response.json()['id']
    
    with open('static.json', 'rb') as f:
        r = requests.request('POST',ewsdir+'api/sdk/files/', files={'static.json': f},auth=HTTPBasicAuth(user, password))
    
    fresource = r.json()
    url = ewsdir+"api/sdk/cybertickets/"+ticket_id+'/attachments'
    headers = {'Content-Type': 'application/json'}
    attach_desc = "Static Analysis File"
    payload = {"description":attach_desc, "fileResource": fresource }
    response = requests.request('POST', url, headers = headers, data = json.dumps(payload), auth=HTTPBasicAuth(user, password))
    

    with open('cti.json', 'rb') as f:
        r = requests.request('POST',ewsdir+'api/sdk/files/', files={'cti.json': f},auth=HTTPBasicAuth(user, password))
    
    fresource = r.json()
    url = ewsdir+"api/sdk/cybertickets/"+ticket_id+'/attachments'
    headers = {'Content-Type': 'application/json'}
    attach_desc = "CTI Analysis File"
    payload = {"description":attach_desc, "fileResource": fresource }
    response = requests.request('POST', url, headers = headers, data = json.dumps(payload), auth=HTTPBasicAuth(user, password))
    

    with open('dynamic.json', 'rb') as f:
        r = requests.request('POST', ewsdir+'api/sdk/files/', files={'dynamic.json': f},auth=HTTPBasicAuth(user, password))
    
    fresource = r.json()
    url = ewsdir+"api/sdk/cybertickets/"+ticket_id+'/attachments'
    headers = {'Content-Type': 'application/json'}
    attach_desc = "dynamic Analysis File"
    payload = {"description":attach_desc, "fileResource": fresource }
    response = requests.request('POST', url, headers = headers, data = json.dumps(payload), auth=HTTPBasicAuth(user, password))
    
    response = jsonify('{success:true}')
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

if __name__ == "__main__":
    app.run(debug=True, port=8000)
    #TODO: Waitress provides production WSGI server with error messages but has no web traffic logging - can be setup with https://docs.pylonsproject.org/projects/waitress/en/latest/logging.html
    #host = '127.0.0.1'#'localhost'
    #port = 8000
    #print("* MAIT WSGI Server started")
    #print("* Served by " + host + " on port " + str(port))
    #serve(app, host=host, port=port)