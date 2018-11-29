#!/usr/bin/python
# -*- coding: utf-8 -*-
#####Begin import modules######
import sys,time,random,re,os
try:
    import requests
except:
    print "no install module requests for setup command down:\npip install requests"
    sys.exit()

try:
    import socket,json
except:
    print "no install module socket or json for setup command down:\npip install socket or json"
    sys.exit()

try:
    from termcolor import colored
except:
    print "no install module termcolor for setup command down:\npip install termcolor"
    sys.exit()
    
try:   
    from bs4 import BeautifulSoup as bs4
    from bs4 import BeautifulSoup
except:
    print "no install module bs4 for setup command down:\npip install bs4"
    sys.exit()    
    
try:    
    import pandas as pd
except:
    print "no install module pandas for setup command down:\npip install pandas"
    sys.exit()

try:
    from tabulate import tabulate
except:
    print "no install module tabulate for setup command down:\npip install tabulate"
    sys.exit()    
#####End import modules######

#####class######
class view_info(object):
    def __init__(self):
	self.WEB_URL_REGEX = r"""(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))"""
	self.user_agents = ["Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
                       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko)",
                       "Mozilla/5.0 (Linux; U; Android 2.3.5; en-us; HTC Vision Build/GRI40) AppleWebKit/533.1",
                       "Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko)",
                       "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201",
                       "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
                       "Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))"]
	self.cls()
	self.banner()
	try:
	    #####Begin try and except######	    
	    self.input = raw_input("\nSelect choice: ")
	    
	    self.URL = raw_input("\nEnter Url or IP: ")
	    
	    if self.input == "1":
		self.Reverse_IP_Domain_Check(self.URL)
	    
	    elif self.input == '2':
		self.Reverse_Whois_Lookup(self.URL)
		
	    elif self.input == '3':
		self.IP_History(self.URL)
		
	    elif self.input == '4':
		self.DNS_Report(self.URL)
		
	    elif self.input == '5':
		self.Reverse_NS_Lookup(self.URL)
		
	    elif self.input == '6':
		self.Reverse_MX_Lookup(self.URL)
		
	    elif self.input == '7':
		self.IP_Location_Finder(self.URL)
		
	    elif self.input == '8':
		print "Coming soon"
		sys.exit()
		
	    elif self.input == '9':
		self.DNS_Propagation_Checker(self.URL)
		
		
	    elif self.input == '10':
		self.Is_My_Site_Down(self.URL)
		
		
	    elif self.input == '11':
		print "Coming soon"
		
	    elif self.input == '12':
		self.Domain_IP_Whois(self.URL)
		
	    elif self.input == '13':
		self.Get_HTTP_Headers(self.URL)
		
	    elif self.input == '14':
		self.DNS_Record_Lookup(self.URL)
		
	    elif self.input == '15':
		self.Port_Scanner(self.URL)
		
	    elif self.input == '16':
		self.Traceroute(self.URL)
		
	    elif self.input == '17':
		self.Spam_Database_Lookup(self.URL)
		
	    elif self.input == '18':
		self.Reverse_DNS_Lookup(self.URL)
		
	    elif self.input == '19':
		self.ASN_Lookup()
		
	    elif self.input == '20':
		self.Ping(self.URL)
		
	    elif self.input == '21':
		self.DNSSEC_Test()
		
	    elif self.input == '22':
		self.URL_String_Decode(self.URL)
		
	    elif self.input == '23':
		self.Abuse_Contact_Lookup()
		
	    elif self.input == '24':
		self.MAC_Address_Lookup(self.URL)
		
	    elif self.input == '25':
		self.Free_Email_Lookup()
		
		
	    else:
		print "Not Selected"
		sys.exit()
	except KeyboardInterrupt:
	    print "ByBy"
	    sys.exit()
	#####end try and except######
	
	
    def Reverse_IP_Domain_Check(self,url):
	site = self.URL
	if site.startswith('http://'):
	    site = site.replace('http://', '')
	elif site.startswith('https://'):
		site = site.replace('https://', '')
	else:
	    pass	
	url = 'https://domains.yougetsignal.com/domains.php'
	Session = requests.Session()
	Session.headers.update({
                    'UserAgent':random.choice(self.user_agents),
                })

	Session = requests.Session()
	params = {"remoteAddress": site}
	request = Session.post(url,data=params) 
	data = json.loads(request.text)
	domain = (data['domainArray'])
	print (colored("[*]",'white')),("\nDomains Found: ")
	print "*/*/*/*/*/*/*/*/*/*/*/*/*/*/"
	for s in domain:
	    for d in s:
		if d != '':
	    
		    print 
		    print (colored("[+]",'blue')),("%s " % d)
	    
	print "*/*/*/*/*/*/*/*/*/*/*/*/*/*/"
	save = raw_input("Do you want the results of Save? yes or no ")
	if save == "yes":
	    result = open("Reverse_IP_Domain_Check.txt",'w')
	    result.write(d)
	    result.close()
	elif save == "no":
	    sys.exit()
	else:
	    print "Not file saved!!"
	    sys.exit()
	    
	    
    def Reverse_Whois_Lookup(self,site):
		url = 'https://viewdns.info/reversewhois/?q='+site
        	Session = requests.Session()
        	Session.headers.update({
                  'UserAgent':random.choice(self.user_agents),
		  'Host' : 'viewdns.info',
          	})

    		request = Session.get(url) 
		res = request.text
		sou = bs4(res, 'html.parser')
		pattern = '^([A-Za-z0-9]\.|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,3}[A-Za-z]{2,6}$'
		rgx = re.compile(pattern)
		fnl = []

		for ent in sou.findAll('td'):
			if rgx.match(ent.text):
				fnl.append(ent.text)

		fnl = list(set(fnl))
		print (colored("[*]",'white')),("Getting list: ")
		for ent in fnl:
			print (colored("[+]",'blue')),("Domain %s" % ent)
    def banner(self):
	self.cls()
	text = 'Script For Info Site or IP'
	print (colored("*"*50,'white'))
	print (colored("[*]",'white')),("Iran-Cyber %s" % text)
	print "\n"+'List Tools:\n'
	print (colored("1  [+]",'red')),("Reverse IP Lookup")
	print (colored("2  [+]",'red')),("Reverse Whois Lookup")
	print (colored("3  [+]",'red')),("IP History")
	print (colored("4  [+]",'red')),("DNS Report")
	print (colored("5  [+]",'red')),("Reverse MX Lookup")
	print (colored("6  [+]",'red')),("Reverse NS Lookup")
	print (colored("7  [+]",'red')),("IP Location Finder")
	print (colored("8  [+]",'red')),("Chinese Firewall Test ")
	print (colored("9  [+]",'red')),("DNS Propagation Checker")
	print (colored("10 [+]",'red')),("Is My Site Down")
	print (colored("11 [+]",'red')),("Iran Firewall Test")
	print (colored("12 [+]",'red')),("Domain / IP Whois")
	print (colored("13 [+]",'red')),("Get HTTP Headers")
	print (colored("14 [+]",'red')),("DNS Record Lookup")
	print (colored("15 [+]",'red')),("Port Scanner")
	print (colored("16 [+]",'red')),("Traceroute")
	print (colored("17 [+]",'red')),("Spam Database Lookup")
	print (colored("18 [+]",'red')),("Reverse DNS Lookup ")
	print (colored("19 [+]",'red')),("ASN Lookup")
	print (colored("20 [+]",'red')),("Ping")
	print (colored("21 [+]",'red')),("DNSSEC Test")
	print (colored("22 [+]",'red')),("URL / String Decode")
	print (colored("23 [+]",'red')),("Abuse Contact Lookup")
	print (colored("24 [+]",'red')),("MAC Address Lookup")
	print (colored("25 [+]",'red')),("Free Email Lookup")	
	
	
	
	
    def IP_History(self,ip):
	url = 'http://viewdns.info/iphistory/?domain='+ip
	Session = requests.Session()
	Session.headers.update({
                    'UserAgent':random.choice(self.user_agents),
                  'Host' : 'viewdns.info',
                })

	request = Session.get(url) 
	res = request.text
	sou = bs4(res, 'html.parser')
	rgx = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
	fnl = []

	for ent in sou.findAll('td'):
	    if rgx.match(ent.text):
		fnl.append(ent.text)

	fnl = list(set(fnl))
	print (colored("[*]",'white')),("Getting list: ")
	for ent in fnl:
	    print (colored("[+]",'blue')),("IP: %s" % ent)   
	    
	    
    def DNS_Report(self,dns):
	url = 'http://viewdns.info/dnsreport/?domain='+dns
	Session = requests.Session()
	Session.headers.update({
                    'UserAgent':random.choice(self.user_agents),
                  'Host' : 'viewdns.info',
                })

	request = Session.get(url) 
	res = request.text
	#sou = bs4(res, 'html.parser')
	rgx = re.findall( r'[0-9]+(?:\.[0-9]+){3}', res )
	print (colored("[*]",'white')),("Getting list: ")
	print "\n"
	print (colored("[*]",'white')),("IP: ")
	for ent in  rgx:
	    print (colored("[+]",'blue')),("IP: %s" % ent)
	    
	print "\n"
	print (colored("[*]",'white')),("Domain: ")
	print "\n"
	for ents in re.findall(self.WEB_URL_REGEX,res):
	    if ents.startswith("https://") or ents.startswith("http://") or ents.endswith(".js") or ents.startswith("viewdns") or ents.startswith("ViewDNS"):
		pass
	    else:
		print (colored("[+]",'blue')),("Domain: %s" % ents)
    
    
    def Reverse_MX_Lookup(self,ip):
	url = 'http://viewdns.info/reversemx/?mx='+ip
	Session = requests.Session()
	Session.headers.update({
                    'UserAgent':random.choice(self.user_agents),
                  'Host' : 'viewdns.info',
                })

	request = Session.get(url) 
	res = request.text
	#sou = bs4(res, 'html.parser')
	#rgx = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
	#fnl = []

	#for ent in sou.findAll('td'):
	    #if rgx.match(ent.text):
		#fnl.append(ent.text)

	#fnl = list(set(fnl))
	print (colored("[*]",'white')),("Getting list: ")
	for ent in re.findall(self.WEB_URL_REGEX,res):
		if ent.startswith("https://") or ent.startswith("http://") or ent.endswith(".js") or ent.startswith("viewdns") or ent.startswith("ViewDNS"):
		    pass
		else:
		    print (colored("[+]",'blue')),("Domain: %s" % ent)	    
		    
    def Reverse_NS_Lookup(self,ns):
	url = 'http://viewdns.info/reversens/?ns='+ns
	Session = requests.Session()
	Session.headers.update({
                    'UserAgent':random.choice(self.user_agents),
                  'Host' : 'viewdns.info',
                })

	request = Session.get(url) 
	res = request.text
	#sou = bs4(res, 'html.parser')
	#rgx = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
	#fnl = []

	#for ent in sou.findAll('td'):
	    #if rgx.match(ent.text):
		#fnl.append(ent.text)

	#fnl = list(set(fnl))
	print (colored("[*]",'white')),("Getting list: ")
	for ent in re.findall(self.WEB_URL_REGEX,res):
		if ent.startswith("https://") or ent.startswith("http://") or ent.endswith(".js") or ent.startswith("viewdns") or ent.startswith("ViewDNS"):
		    pass
		else:
		    print (colored("[+]",'blue')),("Domain_NS: %s" % ent)   
		    
    def IP_Location_Finder(self,ns):
	from bs4 import BeautifulSoup	
	url = 'https://ipleak.net/'+ns
	Session = requests.Session()
	Session.headers.update({
                    'UserAgent':random.choice(self.user_agents)
                })

	request = Session.get(url) 
	res = request.text

	print (colored("[*]",'white')),("Getting list: ")
	print "\n"
	soup = BeautifulSoup(request.content,'lxml')
	table = soup.find_all('table')[0] 
	df = pd.read_html(str(table))
	#print( tabulate(df[0], headers='keys', tablefmt='psql') )	
	print (colored("[+]",'blue')),(tabulate(df[0], headers='keys', tablefmt='psql'))
	
    def DNS_Propagation_Checker(self,dns):
	url = 'http://viewdns.info/propagation/?domain='+dns
	Session = requests.Session()
	Session.headers.update({
                    'UserAgent':random.choice(self.user_agents),
                  'Host' : 'viewdns.info',
                })

	request = Session.get(url) 
	res = request.text
	#sou = bs4(res, 'html.parser')
	rgx = re.findall( r'[0-9]+(?:\.[0-9]+){3}', res )
	print (colored("[*]",'white')),("Getting list: ")
	print "\n"
	print (colored("[*]",'white')),("IP: ")
	for ent in  rgx:
	    print (colored("[+]",'blue')),("IP: %s" % ent)    
	    
    def Is_My_Site_Down (self,site):
	import urllib2
	url = 'http://viewdns.info/propagation/?domain='+site
	result = False
	timeout = 5
	try:
	    result1 =  urllib2.urlopen(url,timeout=timeout).getcode() == 200
	except urllib2.URLError as e:
	    result1 = False
	except socket.timeout as e:
	    result1 = False
	
	ping = response = os.system("ping -c 1 " + site)
	self.cls()
	if response == 0:
	    result = True
	    #print "%s: Network Active " %hostname
	else:
	    result = False
	    #print "%s: Network Error " %hostname
	      
	if result == True or result1 == True :
	    print (colored("[+]",'blue')),("Network Active %s" % site)
	else:
	    print (colored("[+]",'red')),("Network Error %s" % site)
	    
	
    def Domain_IP_Whois(self,ns):
	ip = ns
	DIW = whois.whois(ns)
	print (colored("[*]",'white')),("Getting Whois: ")
	print "\n"
	print (colored("[+]",'blue')),("Domain_IP_Whois: %s" % DIW)  


    def Get_HTTP_Headers(self,site):
	import whois	
	url = site
	check = re.match('(?:http|ftp|https)://', url)
	try:
	    if check:
		r = requests.head(url)
	    else:
		r = requests.head("https://"+url)
	except:
	    print (colored("[+]",'red')),("Unknown Host: %s" % url)
	    sys.exit()
	
	head =  r.headers
	dict = head
	d=" " 
	for  i in dict:
	    a=i
	    b=dict[i]
	    c=i+":"+dict[i]
	    d=d+c+'\n'
	
	print (colored("[*]",'white')),("Getting Head: ")
	print "\n"
	print (colored("[+]",'blue')),("%s" % d)
	
	
    def DNS_Record_Lookup(self,ns):
	url = 'https://viewdns.info/dnsrecord/?domain='+ns
	Session = requests.Session()
	Session.headers.update({
                    'UserAgent':random.choice(self.user_agents),
                    'Host' : 'viewdns.info',
                })

	request = Session.get(url) 
	res = request.text

	print (colored("[*]",'white')),("Getting list: ")
	print "\n"
	soup = BeautifulSoup(request.content,'lxml')
	stats = soup.findAll('table', id = 'null')
	TB = str(stats)
	
	soup2 = BeautifulSoup(TB,"lxml")	
	table = soup2.find_all('table')[1] 
	df = pd.read_html(str(table))
	print (colored("[+]",'blue')),(tabulate(df[0], headers='keys', tablefmt='psql'))    
		    
		    
		    
    def Port_Scanner(self,scan):
	scan = self.URL
	lowPort = 1
	highPort = 65535
	ports = [22, 23, 80, 443, 445, 3389]
	#ports = range(lowPort, highPort)
	result1 = []
	result2 = []
	print (colored("[*]",'white')),("Getting Whois: ")
	print "\n"	
	for port in ports:
	    try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.settimeout(5)
		result = s.connect_ex((scan, port))
		if result == 0:
		    result1.append(port)
		else:
		    result2.append(port)
	    except: 
		pass

	print "\n/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/"
	print (colored("[+]",'blue')),("\n  [+] Port %s" % result1+ "Opened!")
	print "\n"

	print "\n/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/"
	print (colored("[+]",'red')),("\n  [-] Port %s" % result2+ "Closed!")
	print "\n"
	s.close()     
    
    
    
    def Traceroute(self,ip):
	ip = self.URL
	linux = 'traceroute'+ip
	windows = 'tracert'+ip
	os.system([linux, windows][os.name == 'nt'])   
	
	
    def Spam_Database_Lookup(self,hostname):
	url = 'http://viewdns.info/spamdblookup/?ip='+hostname
	Session = requests.Session()
	Session.headers.update({
                    'UserAgent':random.choice(self.user_agents),
                  'Host' : 'viewdns.info',
                })

	page = Session.get(url) 
	soup = BeautifulSoup(page.content,"lxml")
	stats = soup.findAll('table', id = 'null')
	TB = str(stats)
	soup2 = BeautifulSoup(TB,"lxml")
	table = soup2.find_all('table')[2] 
	df = pd.read_html(str(table))
	print (colored("[+]",'blue')),(tabulate(df[0], headers='keys', tablefmt='psql'))
    
    
    def Reverse_DNS_Lookup(self,hostname):
	url = 'http://viewdns.info/reversedns/?ip='+hostname
	Session = requests.Session()
	Session.headers.update({
                    'UserAgent':random.choice(self.user_agents),
                  'Host' : 'viewdns.info',
                })

	page = Session.get(url) 
	soup = BeautifulSoup(page.content,"lxml")
	stats = soup.findAll('table', id = 'null')
	TB = str(stats)
	soup2 = BeautifulSoup(TB,"lxml")
	table = soup2.find_all('table')[0] 
	df = pd.read_html(str(table))
	print (colored("[+]",'blue')),(tabulate(df[0], headers='keys', tablefmt='psql'))
	
	
		
    def ASN_Lookup(self):
	sys.exit()
	
	
	
    def Ping(self,hostname):
	url = 'http://viewdns.info/ping/?domain='+hostname
	Session = requests.Session()
	Session.headers.update({
                    'UserAgent':random.choice(self.user_agents),
                  'Host' : 'viewdns.info',
                })

	page = Session.get(url) 
	soup = BeautifulSoup(page.content,"lxml")
	stats = soup.findAll('table', id = 'null')
	TB = str(stats)
	soup2 = BeautifulSoup(TB,"lxml")
	table = soup2.find_all('table')[1] 
	df = pd.read_html(str(table))
	print (colored("[+]",'blue')),(tabulate(df[0], headers='keys', tablefmt='psql'))    
	
    def DNSSEC_Test(self):
	sys.exit()
		
		
    def URL_String_Decode(self,url):
	url = 'http://viewdns.info/urldecode/?url='+url
	Session = requests.Session()
	Session.headers.update({
                    'UserAgent':random.choice(self.user_agents),
                  'Host' : 'viewdns.info',
                })

	page = Session.get(url) 
	soup = BeautifulSoup(page.content,"lxml")
	stats = soup.findAll('table', id = 'null')
	TB = str(stats)
	soup2 = BeautifulSoup(TB,"lxml")
	table = soup2.find_all('table')[0] 
	df = pd.read_html(str(table))
	print (colored("[+]",'blue')),(tabulate(df[0], headers='keys', tablefmt='psql'))
	
    
    def Abuse_Contact_Lookup(self):
	sys.exit()    
	
	
    def MAC_Address_Lookup (self,mac):
	url = 'https://api.macvendors.com/'+mac
	Session = requests.Session()
	Session.headers.update({
                    'UserAgent':random.choice(self.user_agents)
                })

	page = Session.get(url)    
	print page.text
    
    def Free_Email_Lookup(self):
	print "Coming soon"
	sys.exit()
	
    def cls(self):
	linux = 'clear'
	windows = 'cls'
	os.system([linux, windows][os.name == 'nt'])    
	

view_info()
