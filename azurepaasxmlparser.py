#import required modules-------
import urllib2
import re
import smtplib
import base64
import datetime
import time
from sshfunctions import sshconnect
#------------------------------

#open log file

log = open('c:/scripts/Azure PaaS XML Parser/Logs and Backups/log.txt','a')

'''define firewall list to update Azure PaaS rules on, 
define access creds, smtp relay variable, 
grab and parse XML from Microsoft into ASA commands,
define file to dump ASA commands to as backup

*THIS SCRIPT EXTRACTS ONLY IPV4 RANGES FROM MICROSOFT XML*

'''
#define device access credentials
uname = base64.b64decode('B64 ENCODED UNAME, TO PREVENT SHOULDER SURFING')
pword = base64.b64decode('B64 ENCODED PASSWORD, TO PREVENT SHOULDER SURFING')
#define ASA management IPs
firewalls = ['<LIST OF FIREWALL MGMT IPs']
timestr = str(datetime.datetime.now())
timestr = timestr.replace(" ","")
timestr = timestr.replace(":","")
smtprelay = base64.b64decode("<B64 ENCODED SMTP RELAY, TO PREVENT SHOULDER SURFING")
#open text file to dump ipv4 ranges once converted to ASA syntax, for later reference/comparison
azurepaasipv4list = open('c:/scripts/Azure PaaS XML Parser/Logs and Backups/' + timestr + '.txt',"a")
#find latest direct download link from Azure PaaS range download page
opener = urllib2.build_opener()
opener.addheaders = [('User-agent', 'Mozilla/5.0')]

url = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653"

ourUrl = opener.open(url).read()
ourUrl = ourUrl.split(" ")
for item in ourUrl:
	if 'xml' in item:
		if 'href' in item:
			item = item.replace('href="','')
			item = item.replace('"><span','')
			dynamicurl = item
			break
		
print dynamicurl

#once latest url found in web page, download xml file for parsing
try:
	response = urllib2.urlopen(dynamicurl)
	timestr = str(datetime.datetime.now())
	log.write(timestr + ' - downloaded new XML from Microsoft, parsing' + '\n')
except:
	timestr = str(datetime.datetime.now())
	log.write(timestr + ' - failed to download XML form Microsoft' + '\n')
	
#read response from url download link, which should be XML formatted data
iplistxml = response.read()

#convert cidr notation to subnet mask notation, for ASA CLI
iplistxml = iplistxml.replace('/32',' 255.255.255.255')
iplistxml = iplistxml.replace('/31',' 255.255.255.254')
iplistxml = iplistxml.replace('/30',' 255.255.255.252')
iplistxml = iplistxml.replace('/29',' 255.255.255.248')
iplistxml = iplistxml.replace('/28',' 255.255.255.240')
iplistxml = iplistxml.replace('/27',' 255.255.255.224')
iplistxml = iplistxml.replace('/26',' 255.255.255.192')
iplistxml = iplistxml.replace('/25',' 255.255.255.128')
iplistxml = iplistxml.replace('/24',' 255.255.255.0')
iplistxml = iplistxml.replace('/23',' 255.255.254.0')
iplistxml = iplistxml.replace('/22',' 255.255.252.0')
iplistxml = iplistxml.replace('/21',' 255.255.248.0')
iplistxml = iplistxml.replace('/20',' 255.255.240.0')
iplistxml = iplistxml.replace('/19',' 255.255.224.0')
iplistxml = iplistxml.replace('/18',' 255.255.192.0')
iplistxml = iplistxml.replace('/17',' 255.255.128.0')
iplistxml = iplistxml.replace('/16',' 255.255.0.0')
iplistxml = iplistxml.replace('/15',' 255.254.0.0')
iplistxml = iplistxml.replace('/14',' 255.252.0.0')
iplistxml = iplistxml.replace('/13',' 255.248.0.0')
iplistxml = iplistxml.replace('/12',' 255.240.0.0')
iplistxml = iplistxml.replace('/11',' 255.224.0.0')
iplistxml = iplistxml.replace('/10',' 255.192.0.0')
iplistxml = iplistxml.replace('/9',' 255.128.0.0')
iplistxml = iplistxml.replace('/8',' 255.0.0.0')
iplistxml = iplistxml.replace('<IpRange Subnet=','')
iplistxml = iplistxml.replace('/>','')
iplistxml = iplistxml.replace('"','')
ipv4only = re.sub("^0123456789.","",iplistxml)
ipv4only = ipv4only.splitlines()
formattedlist = []

#for any entry in iplistxml that is not an FQDN, domain name, or ipv6, add it to a new list of formatted subnets called formattedlist
for line in ipv4only:
	if ":" not in line:
		if ".com" not in line:
			if ".net" not in line:
				if ".org" not in line:
					if ".ms" not in line:
						if ".dev" not in line:
							if "<" not in line:
								if "." in line:
									formattedlist.append(line)

#add network-object command to beginning of each list entry, strip unneeded spaces, and add to azurepaasipv4list as a new line
for entry in formattedlist:
	print entry
	formattedentry = "network-object " + entry.strip()
	azurepaasipv4list.write(formattedentry + '\n')

timestr = str(datetime.datetime.now())
log.write(timestr + ' - text file with ASA commands created in script folder' + '\n')	
azurepaasipv4list.close	
#------------------------------

#update azure paas rules on each firewall defined earlier, connection is via Paramiko/SSH module

for firewall in firewalls:
	try:
		#connect to firewall
		try:
			remote_conn = sshconnect(firewall,uname,pword)
			timestr = str(datetime.datetime.now())
			log.write(timestr + " - connecting to "+ firewall + " for updates" + '\n')
		except:
			timestr = str(datetime.datetime.now())
			log.write(timestr + " - failed to connect to "+ firewall + " for updates" + '\n')
			print 'error occurred while attempting ssh connection'
		time.sleep(2)
		#enter enable mode
		remote_conn.send('en\n')
		time.sleep(2)
		#enter enable password
		remote_conn.send(pword +'\n')
		time.sleep(2)
		#enter configure terminal mode
		remote_conn.send('conf t\n')
		time.sleep(2)
		timestr = str(datetime.datetime.now())
		#log.write(timestr + ' - failed to connect to ' + firewall + ' for updates' + '\n')
		time.sleep(5)
		#try to determine inside access list name
		timestr = str(datetime.datetime.now())
		log.write(timestr + ' - determining inbound inside ACL' + '\n')
		output = remote_conn.recv(10000)
		remote_conn.send("show run access-group\n")
		time.sleep(1)
		output = remote_conn.recv(5000)
		if 'ERROR' in output:
			raise Exception("Error while determining inside access list name, confirm interface is named 'inside'")
			timestr = str(datetime.datetime.now())
			log.write(timestr + " - Error while determining inside access list name, confirm interface is named 'inside'" + '\n')
		else:
			for line in output.splitlines():
				if 'inside' in line:
					line = line.split()
					inside_acl = str(line[1])
					timestr = str(datetime.datetime.now())
					log.write(timestr + ' - inside ACL:' + inside_acl + '\n')
		timestr = str(datetime.datetime.now())
		#try to back up inside acl before making changes
		log.write(timestr + ' - backing up current inside ACL' + '\n')
		remote_conn.send('term page 0\n')
		time.sleep(1)
		remote_conn.recv(1000) #clear buffer
		remote_conn.send('show run access-list ' + inside_acl + '\n')
		time.sleep(5)
		aclbackup = remote_conn.recv(200000)
		timestr = str(datetime.datetime.now())
		timestr = timestr.replace(':','-')
		aclbackupfile = open('c:/scripts/Azure PaaS XML Parser/Logs and Backups/' + timestr + '-' + firewall + '-acl-backup.txt','a')
		aclbackupfile.write(aclbackup)
		aclbackupfile.close
		timestr = str(datetime.datetime.now())
		#clear output
		timestr = str(datetime.datetime.now())
		log.write(timestr + ' - adding up to date Azure PaaS object group members' + '\n')
		#add new azure paas object group
		remote_conn.send("object-group network Azure_PaaS_Ranges\n")
		time.sleep(2)
		remote_conn.send('description Microsoft Azure PaaS IP Filter List\n')
		for entry in formattedlist:
			if '*' not in entry:
				formattedentry = "network-object " + entry.strip()
				remote_conn.send(formattedentry + '\n')
				print 'adding ' + formattedentry
				time.sleep(0.5)
				output = remote_conn.recv(500)
				if 'ERROR' in output:
					raise Exception("Issue encountered while adding updated object group")
					timestr = str(datetime.datetime.now())
					log.write(timestr + " - Issue encountered while adding updated object group - " + output + '\n')
		#add ACL entries back to bottom of inside ACL	
		timestr = str(datetime.datetime.now())
		log.write(timestr + ' - adding ACL entry back to bottom of ACL' + '\n')
		remote_conn.send("access-list " + inside_acl + " permit tcp any object-group Azure_PaaS_Ranges object-group Azure_PaaS_TCP\n")
		time.sleep(3)
		remote_conn.send("access-list " + inside_acl + " permit udp any object-group Azure_PaaS_Ranges object-group Azure_PaaS_UDP\n")
		time.sleep(3)
		#save configuration
		timestr = str(datetime.datetime.now())
		log.write(timestr + ' - saving configuration on firewall' + '\n')
		remote_conn.send("wr\n")
		time.sleep(2)
		timestr = str(datetime.datetime.now())
		log.write(timestr + " - successfully updated azure paas rules on " + firewall + '\n')
	except:
		timestr = str(datetime.datetime.now())
		log.write(timestr + ' - general failure' + '\n')
		timestr = str(datetime.datetime.now())
		log.write(timestr + " - general failure" + '\n')


log.close	
#------------------------------

#define smtp settings for email update, send email update
sender = '<SENDER EMAIL>' #set smtp params
receiver = ['<RECIPIENT EMAIL>'] #set smtp params
message = 'Subject: {}\n\n{}'.format('New Azure PaaS IP Ranges Created',""" 
----------------------------------------------------------------------------------
New Azure PaaS Network Object Config Created and Pushed to Perimeter Firewalls
----------------------------------------------------------------------------------

""") 
smtpObj = smtplib.SMTP(smtprelay) #set smtp params
smtpObj.sendmail(sender, receiver, message) #set smtp params and send email
#------------------------------