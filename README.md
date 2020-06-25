
### Features

 - Read request file from burp suite intercept. 
 - WAF fingerprint:
	 - Mod_Security
	 - WebKnight
	 - Cloudflare
	 - FortiWeb
	 - Imperva Incapsula
	 - GoDaddy
	 - ASP.NET Generic
	  
 - Web Protection fingerprint:
	 - Clickjacking
	 - CloudFlare protection
	 - CSRF token


### Tested on 

 - http://vulnweb.lab.rz.my/user/login.php
 - https://grabme.herokuapp.com/target/


### Installation
 1. Python 3 
 1. run 'bash install.sh' to auto-install module in requirements.txt
 2. chmod +x httpwaf.py


### Usage

    python3 httpwaf.py -r labrz_req.txt -c credpwd.txt -u email -p password -i "User Email doesn't exists."

