#!/usr/bin/python3
import csv, os, subprocess, sys, time, matplotlib, pandas, threading

import pandas as pd
import numpy as np
#import matplotlib.pyplot as plt

from multiprocessing.dummy import Pool

## steps
#    1) find mail servers 
#    2) find all web servers
#    3) run nmap on all server enpoints found in 1 & 2 and report open ports
#    4) find tls configuration for all servers running on port 443 
#    5) find all http security headers

# For printing results
class color:
	PURPLE = '\033[95m'
	CYAN = '\033[96m'
	DARKCYAN = '\033[36m'
	BLUE = '\033[94m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	END = '\033[0m'

class options:
	WWW = "-sW"
	MX = "-sM"
	IPV4 = "4"
	IPV6 = "6"
	PORTS = "-p"
	CIPHER = "-c" 




#def read_results(domain, 
# displays info for testing purposes
def print_hosts(host_list, domain):
	for host in host_list:
		print("Report for %s" %(host["Host"]))
		print(" Address:  %s \n Port | Service" %(host["IPv4"]))
		for port in host["Ports"]:	
			print('  {}  |  {}'.format(port[0],port[1]))
		print('\n')

	
def print_tls(tls):
	print("TLS version detection for www." + domain + "\n")
	for v in tls:
		print(v["TLSv"])
		for c in v["Ciphers"]:
			print("	 " + c)


# initializes a dict for given domain
def init_domain(domain):
	host_server_list = [] # raw host values

	mx_list, mx_total = mx_discovery(domain)
	host_server_list.extend(mx_list)

	#host_server_list.extend(www_discovery(domain))

	if (len(host_server_list) == 0):
		print('\nNo hosts discovered. Exiting...')
		return

	host_dicts = [] # a list of dictionaries holding host information
	# makes a dictionary for every host that has been discovered so far

	for server in host_server_list:
		ipv4, ipv6 = init_addr(server)

		#Organization = whois(host_server_list[0])
		ports = port_scan(ipv4) # call to port_scan
		host = {'Domain':domain, 'Host':server, 'IPv4':ipv4, 'IPv6':"NULL", 'MX':mx_total, 'Ports':ports}	
		host_dicts.append(host)
	write_results(host_dicts, 'host_results.csv')
#	return host_dicts

### INCOMPLETE ###
def whois(addr):
	reader = subprocess.Popen(['whois ' + addr], stdout=subprocess.PIPE, shell=True)
	org_info = []	
	temp = True		
	while temp:
		line = reader.stdout.readline()
		line = line.decode("utf-8")		
		if not line:
			temp = False
			break
		start = line.find(' by ') +4
		host = line[start:-1]

# uses reverse dns lookup of mx server to find address range for ipv4
def mx_discovery(domain):

	mx_list = []
	reader = subprocess.run(['host -t mx ' + domain], stdout=subprocess.PIPE, timeout=60, universal_newlines=True, shell=True)
	i = 0
	temp = True	
#	while temp:
#		line = reader.stdout.readline()
#		line = line.decode("utf-8")
	lines = reader.stdout.splitlines()
	for line in lines:
		if not line:
			temp = False
			break

		start = line.find(' by ')+4		
		for char in line[start:-1]:
			if(char.isdigit()):
				start+=1
			else:
				start+=1
				break
		host = line[start:-1]
		mx_list.append(host)
		i+=1
	return mx_list, i

def host_discovery(domain):
	print('Host Discovery...')
	host_list = []
	domain = "target.com"
	reader = subprocess.run(['nmap --script dns-srv-enum --script-args  \"dns-srv-enum.domain=\'' + domain + '\'\"'], stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
	i =0
	loop = True
	temp = False	
	lines = reader.stdout.splitlines()
	for line in lines:
		if not line:
			loop = False
			break
		if (temp==True and line[0] == 'W'):
			loop = False
			break
		elif (temp == True):
			host = line[30:-1]
			host_list.append(host)
			i+=1
		if(" service   prio " in line):
			temp = True


	if (len(host_list) == 0):
		print('No mail servers discovered...')
	else:
		print("  %s mx servers discovered.\n" %(i))
	return mx_list

# uses host command to find ipv4 and ipv6 addr
def init_addr(host):
	cmd = "host -4 " + host
	with open("tmp.txt", 'w') as f:
		reader_a = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=f, timeout=60, universal_newlines=True, shell=True)		
	ipv4 = []
	ipv6 = "NULL"
	
	lines = reader_a.stdout.splitlines()
	for line_a in lines:
		if(line_a.find(' address ')):
			start_a = line_a.find(' address ')+9

		if(line_a[start_a].isdigit()):	
			ip = line_a[start_a:]
			ipv4.append(ip)
	return ipv4, ipv6

def port_scan(addr): # returns list of ports
	reader = subprocess.run("nmap -sS -T5 --host-timeout 2m " + addr, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, universal_newlines=True, shell=True)
#	ports = []
	tcp = []
	udp = []		
	temp = True	
	lines = reader.stdout.splitlines()
	for line in lines:
		if not line:
			temp = False
			break
		if line[0].isdigit():

			start = line.find('/')
			port = line[0:start]
			start+=1
			end = line.find('/')+4
			protocol = line[start:end]
			if(protocol == "tcp"):
				tcp.append(port)
			elif(protocol == 'udp'):
				udp.append(port)
			#ports.append((port,protocol))
	#return ports
	return tcp, udp

def tls_version_detection(domain):
	reader = subprocess.Popen(["nmap -sV --script ssl-enum-ciphers -p 443 www." + domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, universal_newlines=True, shell=True)
	tls_list = []
	tls = []	
	temp = True
	for line in reader.stdout:
		if not line:
			temp = False
			tls_list.append(ver_info)
			break

		# finds tls version in command output. initializes a new dict to append to list
		if(line[4:7] == "TLS"): 
			if("ver_info" in locals()):
				tls_list.append(ver_info)
			ciphers = []	
			ver_info = {'Domain':domain, 'TLSv':line[8:11], 'Ciphers':ciphers}	
			tls.append(line[4:11])

		# finds cipher info and saves to dict
		if(line[8:12] == "TLS_"): 
			ver_info['Ciphers'].append(line[8:-1])

	write_results(tls_list, 'host_results.csv')
	

def write_results(dict_list, file_path):
	# checks whether file path exists to see if header needs to be written
	file_exists= os.path.isfile(file_path)
	keys = list(dict_list[0].keys()) 

 	# opens/creates target csv file for appending
	host_file = open(file_path, 'a')
	writer = csv.DictWriter(host_file, fieldnames=keys) 

	# writes the keys in header if the file was just created
	if not file_exists:
		writer.writeheader() 
	
	# writes each dictionary in the list to a row
	writer.writerows(dict_list) 
	host_file.close()


def plot_bar():
	with open('tls_results.csv', 'r', newline='') as csvfile:
		reader = csv.reader(csvfile, delimiter=',')
		#for row in reader:

#	plt.plot([host['TLSv'] for data in host_list],
 
 #            marker)

	a_dictionary = {"a": 1, "b": 2, "c": 3}
	keys = a_dictionary.keys()
	values = a_dictionary.values()
	plt.bar(keys, values)

def read_results(file, ex, incl, ran, port, sort):

	# make dictionary out of csv file
	with open(file, "r") as f:
		print("Reading %s..." % file) 
		reader = csv.DictReader(f)
		df_dict = list(reader)
		

	# loop dictionary and include/exclude domains
	list_dicts = []


	count=0   #int(ran[1][1])	
	for d in df_dict:
		if((count > ran) and count < len(df_dict)):#[0]:
			break
			
		if (d["Domain"] in incl):
			list_dicts.append(d)
	
	if("all" in incl):
		list_dicts = df_dict

	list_dicts = [x for x in list_dicts if x["Domain"] not in ex]

	df = pd.DataFrame(list_dicts)
	print(df.describe())
	print(df)
	
			

			# 



# initializes a dict for given domain
def init_domain2(server, domain):
	host_dicts = []
	ipv4, ipv6 = init_addr(server)
	for ip in ipv4:
		#ports = port_scan(ip) # call to port_scan
		tcp, udp = port_scan(ip)		
		host = {'Domain':domain, 'Host':server, 'IPv4':ip, 'IPv6':ipv6, 'TCP':tcp, 'UDP':udp}	
		host_dicts.append(host)
	
	if(len(host_dicts)>0):
		write_results(host_dicts, 'host_results.csv')

def www_driver(domain):
	tls = tls_version_detection(domain)

def mx_driver(domain):
	mx_list, mx_total = mx_discovery(domain)
	if (len(mx_list) == 0):
		return

	# makes a dictionary for every host that has been discovered so far
	thread_list = []
#	for server in mx_list:
#		thread = threading.Thread(target=init_domain2, args=(server,domain))
#		thread_list.append(thread)
#		thread.start()

#	for thread in thread_list:
#		thread.join()


	for server in mx_list:
		init_domain2(server, domain)

def CLI(): 
	return

if __name__ == "__main__": #driver
	subprocess.run(['clear'], stdout=subprocess.PIPE, shell=True)
	print("##########################")
	print("##  Cyberscope Project  ##")
	print("##########################\n")
	while True:
		cmd = input("> ")
		if(cmd == "q"):		
			break;

		# performs initial scan
		elif(cmd == "run"):
			infile = "top-1m.csv"
			d_list = []			
			with open(infile) as f:
				reader = csv.reader(f, delimiter=',')
				line = 0;
				print("Performing scan...\n")
				for row in reader:
					if(line==1000):
#						d_list.append(row[1])
						break;
					#print(line)
					line+=1
					d_list.append(row[1])


#			for d in d_list:				
#				print(d)

#			print(len(d_list))	
			start = time.time()


#			tlist_mx = []
#			for d in d_list:
#			    thread = threading.Thread(target=mx_driver, args=(d,))
#			    tlist_mx.append(thread)
#			    thread.start()

#			for thread in tlist_mx:
#			    thread.join()

#			tlist_www = []
#			for d in d_list:
#			    thread = threading.Thread(target=www_driver, args=(d,))
#			    tlist_www.append(thread)
#			    thread.start()

#			for thread in tlist_www:
#			    thread.join()

			count = 0
			for domain in d_list:
				count+=1
				mx_driver(domain)
				print(count)
		
			end = time.time()
			t_total = end - start
			print(f"total Time: {t_total}")
				
		# removes files
		elif(cmd[0:2] == "rm"):
			if(cmd[3:] == "-t"):
				subprocess.Popen(['rm tls_results.csv'], stdout=subprocess.PIPE, shell=True)
			elif(cmd[3:] == "-mx"):
				subprocess.Popen(['rm host_results.csv'], stdout=subprocess.PIPE, shell=True)
			else:
				print("invalid option. please specify file type with -t or -h")	

		# reads/prints results
		elif(cmd[0:4] == "read"):
			loc = cmd.find("-s")
						
			args = cmd[loc:]			
			if True:
				read_results(d_list, args)
			else:
				print("invalid options.")
	
		elif(cmd == "plot"):
			plot_bar()

		# Help page
		elif(cmd == "help"):
			print(color.BOLD + "\nCyberscope Help Page\n" + color.END)
			print(color.BOLD + color.UNDERLINE + "Commands" + color.END + ":\n")
			
			# rm command
			print(color.BOLD + "rm" + color.END)
			print("  " + color.UNDERLINE + "Description" + color.END)
			print("    Deletes specified data")
			print("  " + color.UNDERLINE + "Options" + color.END)
			print("    -t	" + color.UNDERLINE + "specifies all discovered web server tls/ssl data" + color.END)
			print("    -mx	" + color.UNDERLINE + "specifies all discovered mx server data" + color.END)
			# read command
			print(color.BOLD + "\nread" + color.END)
			print("  " + color.UNDERLINE + "Description" + color.END)
			print("    Prints data from results file. Options avaiable to sort for specific data. Some options void the use of others and the first option will be utilized. Options are listed in priority order")
			print("  " + color.UNDERLINE + "Options" + color.END)
	
			# data specification 

			print("    -sW" + color.BOLD + " or" + color.END + " -sM") 
			print(color.UNDERLINE + "	sW signifies web server, and sM specifies mail servers. conflict emerges if both are options. one of these always has to be used" + color.END)
				# possible future additions - adding option to auto complete domain entry and sort by what is given. eg '-d n' would result in listing all domains that begin with n
			print("    -d {domain(s)}")
			print(color.UNDERLINE + "	sorts and prints data only with specified domain names. use ' ' to seperate entries" + color.END)
			

			print("    -p {ports(s)}" + color.UNDERLINE + "     sorts by open ports. use '-' to signify a range of values or ',' to seperate values" + color.END)
			

			# https security 
			print("    -hA	" + color.UNDERLINE + "only lists results that have web servers that accept TLSv1.1" + color.END)
			print("    -hB	" + color.UNDERLINE + "only lists results that have web servers that accept TLSv1.2" + color.END)
			print("    -hC	" + color.UNDERLINE + "only lists results that have web servers that accept TLSv1.3" + color.END)
			print("    -c {cipher(s)}	" + color.UNDERLINE + "only lists results that encrypt transmission with a specified cipher" + color.END)
			# printing options
			print("    -4	" + color.UNDERLINE + "prints ipv4 address of host" + color.END)
			print("    -6	" + color.UNDERLINE + "prints ipv6 address of host" + color.END)
			print("    -t	" + color.UNDERLINE + "prints domain names by total number of specified option in descending order" + color.END)

			print(color.UNDERLINE + "Enter 'q' to quit" + color.END)
		

		else:
			print("Invalid command. enter 'help' for command options...\n")	





