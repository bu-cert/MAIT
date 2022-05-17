# MAIT: Malware Analysis and Intelligence Toolkit

**This work has received funding from the European Union’s Horizon 2020 research and innovation program under the grant agreement no 830943 (ECHO).**

Please see the video of MAIT for a quick introduction:

https://echonetwork.eu/mait/
 
 and
 
https://www.youtube.com/watch?v=cOkhQafhwm8

An automated and behaviour-based malware analysis toolkit that identifies potential malicious executables files (.exe, .dll) and collect Cyber Threat Intelligence for the file by using online resources.  

By utilising a BU-CERT instance of open source state-of-the-art malware static and dynamic analysers (such as cuckoo sandbox) and with the use of open source malware databases, this tool aims to provide a malware signature along with an intelligence report collected from public sources.  

The contents of the report include (but are not limited to) the following;  

* Chronological data about the malicious file, i.e. first appearance, increase in time  
* Any weaponisation in any APT campaigns or cyberattacks in general 
* Public information on cyber attribution 
* Related vulnerabilities and information on relevance 

The tool will seamlessly integrate with the ECHO Early Warning System to share this information as a CTI within the organisation and with member constituencies/organisations. 

# Dependencies
Install radare2: 

For static analysis tasks MAIT requires R2 program. To install radare2:
https://rada.re/n/

Install Cuckoo Sandbox:
https://cuckoosandbox.org/

MAIT also collects intelligence from the following sources, in order to run MAIT, you require API keys from the following platforms: 

* Abuse.ch
* Malware Bazaar
* AlienVault
* VirusTotal
* FarsightSecurity
* Ip2proxy
* ThreatIntelligencePlatform
* SecurityTrails
* GreyNoise

```
pip -r install requirements
```

In addition to the software requirements, MAIT assumes you have a Cuckoo sandbox running. 

# Run
**Before running MAIT, enter all the api keys and configuration information to the config file in the root directory.**
Run:

```
python3 dispatcher.py
```
the MAIT engine is being served on the port 8000. 

# Web Interface
MAIT also comes with a Web interface, you can serve the web interface with any web server, an example server would be npm's http-server:

Install Nodejs 
```
sudo apt-get install -y nodejs
```
Install http-server
```
npm install http-server
```
run the webserver within the **Web** folder
```
http-server
```










