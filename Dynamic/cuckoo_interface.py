import requests
import json
import configparser

class Dynamic:

    def __init__(self):
        config = configparser.ConfigParser()
        config.read('./config.txt')
        self.BASEDIR = config['cuckoo']['BASEDIR']
        self.options = {"options": ["procmemdump=yes", "memory=yes"]}

    def post_submit(self,apicall, files):
        REST_URL = self.BASEDIR+apicall
        HEADERS = {"Authorization": "Bearer 5oJkH42IbX5cK42-eXQSqw"}
        r = requests.post(REST_URL, headers=HEADERS, files=files, data=self.options)
        return r
    def getreq_cuckoo(self,apicall):

        REST_URL = self.BASEDIR+apicall
        HEADERS = {"Authorization": "Bearer 5oJkH42IbX5cK42-eXQSqw"}
        r = requests.get(REST_URL, headers = HEADERS, data=self.options)
        return r

    def submit_file(self,url):
        apicall = "tasks/create/file"
        with open(url, "rb") as sample:
            files = {"file": ("malware to be analysed", sample)}
            r = self.post_submit(apicall, files)

        if r.status_code == 200:
            task_id = r.json()["task_id"]
            print("file is submitted with the task id " + str(task_id))
            return task_id
        else:
            print("error occured: "+ str(r.status_code))

    def get_status(self):
        
        apicall = "cuckoo/status"
        r= self.getreq_cuckoo(apicall)
        if r.status_code == 200:
            return(r.text)
        else:
            print("error occured: "+ str(r.status_code))

    def get_tasklist(self):
        apicall = "tasks/list"
        r= self.getreq_cuckoo(apicall)
        if r.status_code == 200:
            return(r.text)
        else:
            print("error occured: "+r.text +str(r.status_code))

    def is_finished(self,task_id):
        apicall = "tasks/view/"+str(task_id)
        r= self.getreq_cuckoo(apicall)
        if r.status_code == 200:
            if r.json()["task"]["status"] == "reported":
                return True
            else:
                return False
        else:
            print("error occured: "+ str(r.status_code))

    def get_report(self,task_id):
        apicall = "tasks/report/"+str(task_id)
        r= self.getreq_cuckoo(apicall)
        if r.status_code == 200:
            return r.text
        else:
            print("error occured: "+ str(r.status_code))

    def get_apicalls(self,report):
        report = json.loads(report)
        apis = []
        if 'signatures' in report.keys():
            signatures = report["signatures"]
            for i in signatures:
                if i["markcount"] != 0:
                    marks = i["marks"]
                    for j in marks:
                        if "call" in j.keys():
                            apis.append(j)
        return apis

    def get_ttps(self,report):
        report = json.loads(report)
        ttps = []
        if 'signatures' in report.keys():
            signatures = report["signatures"]
            for i in signatures:
                if i["ttp"] != {}:
                    ttps.append(i["ttp"])
            return ttps

    def get_summary(self,report):
        report = json.loads(report)
        summary = []
        if 'behavior' in report.keys():
            summary = report["behavior"]        
        return summary
        
    def get_signatures(self,report):
        report = json.loads(report)
        signatures = []
        if 'signatures' in report.keys():
            signatures = report["signatures"]        
        return signatures

    def get_network(self,report):
        report = json.loads(report)
        network = []
        if 'network' in report.keys():
            network = report["network"]
        return network

    def get_dropped_files(self,report):
        report = json.loads(report)
        droplist = []
        if 'dropped' in report.keys():
            dropped = report['dropped']
            for i in dropped:
                droplist.append(i['sha1'])
        return droplist
