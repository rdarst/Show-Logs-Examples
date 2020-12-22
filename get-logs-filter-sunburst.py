#!/usr/bin/python3

import getopt
import requests
import sys
import json
import os
import time

user = ''
password = ''
mgmtserverip = ''
domain = ''

if len(sys.argv) <= 6:
   print ('Error - Format should be - get-logs-filter-sunburst.py -u <username> -p <password> -s <mgmt_server_ip> -d <MDS_Domain_Name>')
   print ('MDS_Domain_Name is optional')
   exit(1)

try:
    opts, args = getopt.getopt(sys.argv[1:],"u:p:s:d:", ['usr=','pass=','serverip=', 'domain=', 'help'])
except getopt.GetoptError:
   print ('Error - Format should be - get-logs-filter-sunburst.py -u <username> -p <password> -s <mgmt_server_ip> -d <MDS_DOMAIN_NAME_Optional>')
   sys.exit(2)
for opt, arg in opts:
   if opt in ('-h', '--help'):
      print('get-logs-filter-sunburst.py -u <username> -p <password> -s <mgmt_server_ip>')
      sys.exit()
   elif opt in ("-u", "--usr"):
      user = arg
   elif opt in ("-p", "--pass"):
      password = arg
   elif opt in ('-s', '--serverip'):
      mgmtserverip = arg
   elif opt in ('-d', '--domain'):
      domain = arg


# Set login info
url = "https://" + mgmtserverip + "/web_api/login"
if domain is None: 
    payload = { 
        "user" :  user, 
        "password" : password,
        "session-timeout" : 3600,
        "read-only" : "true"
        }
else:
    payload = {
        "user" :  user,
        "password" : password,
        "domain" : domain,
        "session-timeout" : 3600,
        "read-only" : "true"
        }
headers = {
    'Content-Type': "application/json",
    'Cache-Control': "no-cache",
    }

# SSL Certificate Checking is disabled!!!
requests.packages.urllib3.disable_warnings()
try:
    response = requests.request("POST", url, data=json.dumps(payload), headers=headers, verify=False)
    response.raise_for_status()
except requests.exceptions.HTTPError as err:
    print(err) 
    print("Did the login fail?")
    sys.exit()

sid_json = json.loads(response.text)
if sid_json['api-server-version']=='1.7' or sid_json['api-server-version']=='1.6.1':
   print("API-Server Version is " + sid_json['api-server-version'])
   print("export CHKP_SID=\"" + sid_json['sid'] + "\"")
   print("export CHKP_SERVER=\"https://" + mgmtserverip + "/web_api\"")

   while True:

         # Get top sources for Sunburst Logs 
         url = "https://" + mgmtserverip + "/web_api/show-logs" 
         query_object = {
           "new-query": {
           "time-frame": "today",
           "max-logs-per-request": "100",
           "top": { 
                    "field" : "sources",
                    "count" : "25"  
                    },
           "filter": "(blade:Anti-Virus AND (\"Trojan.Win32.SUNBURST.TC.*\")) OR (blade:\"Threat emulation\" AND (HackTool.Wins.FE_RT.A*)) OR  (blade:Anti-Bot AND (protection_name:(\"Backdoor.Win32.SUNBURST.*\" OR \"Backdoor.Win32.Beacon.*\" OR \"Trojan.Win32.Rubeus.*\"))) OR (blade:IPS AND attack_name:\"Sunburst Backdoor Suspicious Traffic\") OR (\"solartrackingsystem.net\" OR \"virtualdataserver.com\" OR \"avsvmcloud.com\" OR \"freescanonline.com\" OR \"databasegalore.com\" OR \"digitalcollege.org\" OR \"incomeupdate.com\" OR \"deftsecurity.com\" OR \"highdatabase.com\" OR \"websitetheme.com\" OR \"thedoccloud.com\" OR \"panhardware.com\" OR \"avsvmcloud.com\" OR \"lcomputers.com\" OR \"zupertech.com\" OR \"kubecloud.com\" OR \"webcodez.com\" OR \"13.59.205.66\" OR \"54.193.127.66\" OR \"54.215.192.52\" OR \"34.203.203.23\" OR \"139.99.115.204\" OR \"5.252.177.25\" OR \"5.252.177.21\" OR \"204.188.205.176\" OR \"51.89.125.18\" OR \"167.114.213.199\" OR \"avsvmcloud.com\" OR *sunburst* OR *hacktool.wins.FE_RT*)"
       }
   }
         query_dump = json.dumps(query_object)

         headers = {
            'Content-Type': "application/json",
            'Cache-Control': "no-cache",
            'X-chkp-sid': "" + sid_json['sid'] + "",
            }

         # SSL Certificate Checking is disabled!!!
         requests.packages.urllib3.disable_warnings()
         response = requests.request("POST", url, data=query_dump, headers=headers, verify=False)
         data = {}
         for tops in response.json()["tops"]:
           for k,v in tops.items():
             data[k] = v
      
         open("logs_sunburst.json", "w").write(
           json.dumps(data, sort_keys=False, indent=4, separators=(',', ': '))
            )
         print("JSON data for logs sent to logs_sunburst.json")
         print("Sleeping for 300 seconds before getting more data")
         print(data)
         time.sleep(300)
else: 
   print("API-Server Version 1.7(R81) or 1.6.1(R80.40 JHF78 or later) is required.")
   print("API-Server Version is " + sid_json['api-server-version'])
