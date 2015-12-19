#!/usr/bin/python

#############################################################
# Script to Spider IP's for open ports                      #
# written by redN00ws @ Cleveridge                          #
#############################################################
#                                                           #
#        C l e v e r i d g e - Ethical Hacking Lab          #
#                 (https://cleveridge.org)                  #
#                                                           #
#############################################################
# Contribution from                                         #
#  - none yet                                               #
#############################################################
#                                                           #
version = "V1.00"                                           #
build = "007"                                               #
# Discovery edition                                         #
#############################################################

import getpass
import glob
import math
import os
import re
import socket
import ssl
import sys
import threading
import time
try:
    import urllib.request as urllib2
except ImportError:
    import urllib2
from datetime import datetime
from random import randint
from subprocess import Popen, PIPE


# Scanning ports
sPortsTCP = {
    20 : 'FTP',
    21 : 'FTP',
    22 : 'SSH',
    23 : 'Telnet',
    25 : 'SMTP',
    43 : 'WHOIS',
    53 : 'DNS',
    69 : 'TFTP',
    80 : 'HTTP',
    81 : 'Torpark - Onion routing',
    110 : 'POP',
    123 : 'NTP',
    135 : 'RPC',
    137 : 'NetBios Name Service',
    138 : 'NetBios Datagram Service',
    139 : 'NetBios Session Services',
    143 : 'IMAP',
    156 : 'SQL Server',
    194 : 'IRC - Internet Relay Chat',
    300 : 'ThinLinc Web Access',
    311 : 'Mac OS X Server Admin',
    389 : 'LDAP',
    401 : 'UPS - Uninterruptible Power Supply',
    407 : 'Timbuktu',
    443 : 'HTTPS',
    445 : 'SMB',
    491 : 'GO-Global Remote Access',
    504 : 'Citadel - Multiservice Protocol',
    514 : 'Shell',
    587 : 'SMTP',
    631 : 'CUPS - Common Unix Printing System',
    660 : 'Mac OS X Server admin',
    901 : 'SAMBA Web Admin / VMware',
    991 : 'NAS - Network Admin System',
    1010 : 'Trojan Dolly / ThinLink',
    1080 : 'SOCKS proxy',
    1194 : 'OpenVPN',
    1433 : 'MS SQL',
    1494 : 'Citrix ICA',
    1604 : 'Darkcomet RAT server',
    2222 : 'Direct Admin',
    3299 : 'SAP-Router (routing application proxy for SAP R/3)',
    3306 : 'MySQL',
    3389 : 'Remote Desktop Protocol',
    4040 : 'Kerio Connect Web Admin',
    4444 : 'Astaro Web Admin',
    4899 : 'Radmin - remote administration tool',
    5060 : 'SIP',
    5061 : 'SIP over TLS',
    5412 : 'IBM Rational Synergy Message Router',
    5450 : 'OSIsoft PI Server Client Access',
    5631 : 'pcAnywhere',
    5632 : 'pcAnywhere',
    6665 : 'IRC',
    6666 : 'IRC / Beast RAT',
    6667 : 'IRC',
    6668 : 'IRC',
    6669 : 'IRC',
    7071 : 'Zimbra Admin Console',
    7474 : 'Neo4J Server webadmin',
    7777 : 'Kloxo control Panel SSL',
    7778 : 'Kloxo control Panel',
    8000 : 'iRDMI (Intel Remote Desktop Management) / Nortel Contivity Router Firewall User Authentication',
    8008 : 'HTTP Alt.',
    8080 : 'HTTP Alt.',
    8291 : 'Winbox : MicroTik Router OS for Windows',
    8443 : 'Plesk Admin Panel SSL',
    8880 : 'Plesk Admin Panel',
    8081 : 'Raspberry Pi Motion (camera)',
    9001 : 'Cisco-xremote Router Config',
    10000 : 'Webmin Admin',
    12345 : 'NetBus: Remote Administration tool (often Trojan)',
    15672 : 'RabbitMQ Messaging System UI',
    23476 : 'Donald Dick RAT',
    23477 : 'Donald Dick RAT',
    32764 : 'Linksys Router backdoor',
    40421 : 'Masters Paradise',
    40422 : 'Masters Paradise',
    40423 : 'Masters Paradise',
    40424 : 'Masters Paradise',
    49608 : 'Netmeeting Remote Control',
    49609 : 'Netmeeting Remote Control',
    54320 : 'BO2K RAT',
    65301 : 'pcAnywhere'
}
    
#++ BASIC SETTINGS //#
threads = 5
finallog = "\n"
logresults = {}
cachefile  = str(randint(1000000000, 9999999999)) + '.data'




#++ FUNCTIONS //#

# func Writelog
def func_writelog(how, logloc, txt): # how: a=append, w=new write
   with open(logloc, how) as mylog:
      mylog.write(txt)

def func_addToFinalLog(txt):
    global finallog
    finallog = finallog + "\n" + txt


# func ScanHost
def func_scanhost(ip, logloc):   
   # Log Key
   ipchunks = ip.split('.')
   logkey = int(ipchunks[3])
   
   # Log Scan
   txt = "\n*****************************\nResults IP : %s" % (ip)
   
   # create log result for this IP
   if not ip in logresults :
       logresults[logkey] = txt + '\n'
       
       # try to ping to see machine is active
       try :
           png = Popen(["ping", "-c2", ip], stdout = PIPE)
           pngreturn = png.communicate()[0]
           if "0 received" in pngreturn :
               txt = "   | PING : ip not responding"
           else : txt = "   | PING : ACTIVE MACHINE -> RESPONDING"
       except Exception as e:
           txt = "   | PING : error %e" % (e)
       logresults[logkey] = logresults[logkey] + txt + '\n'
       print(txt)
           
       
   
   # Walk Through Ports
   for item in sorted(sPortsTCP):
       
       # check if port is open
       sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       sock.settimeout(5.0)
       html = False
       
       try: 
           result = sock.connect_ex((ip, int(item)))
        	
           if result == 0: # if port is open
              txt = "   |=> Port %s (%s) is accessible." % (item, sPortsTCP[item])
              logresults[logkey] = logresults[logkey] + txt + '\n'
              print(txt)
              html = True
                                                         
              reply = sock.recv(4096)
              txt = "   |   %s" % (reply.encode('iso-8859-1')) 
              logresults[logkey] = logresults[logkey] + txt + '\n'
              print(txt)              
              
           else: # if port is closed
              txt = "|- Port %s closed." % (item)
              print(txt)
       except socket.timeout:
          print("Timed out")
       except :
          print("Closed")
       
       # Try to find html page titles on possible HTML ports
       if (item == 80 or item == 443 or item == 8008 or item == 8080) and html == True :
           if item == 443:
               thisurl = 'https://' + str(ip) + ':' + str(item)
           else:
               thisurl = 'http://' + str(ip) + ':' + str(item)
           print('url : ' + thisurl)
           
           try:
               page = urllib2.urlopen(thisurl, timeout=5).read()
               title = func_titleFilter(page)
               txt = "   |   %s" % (title.encode('iso-8859-1')) 
               logresults[logkey] = logresults[logkey] + txt + '\n'
           except urllib2.URLError as e: # In case of Basic Authentication and other errors
               txt = "   |   Alert : %s" % e
               logresults[logkey] = logresults[logkey] + txt + '\n'
           except: # In case of other errors
               print('Not able to read url')
           txt = "   |   %s" % (thisurl) 
           logresults[logkey] = logresults[logkey] + txt + '\n'
              
   
   # print results
   func_writelog("a", logloc, logresults[logkey] + "\n")

# func CheckIPrange
def func_checkIPrange(ip_range):
   print('Checking IP range... '),
   reply = False
   posHyphen = ip_range.find('-')
   if int(posHyphen) > 6 and int(posHyphen) <= 15 :
      ip_first = ip_range[:posHyphen]
      ip_untill = ip_range[posHyphen +1:]
      ip_first_parts = ip_first.split('.')
      if len(ip_first_parts) == 4 :
         try :
            if (int(ip_first_parts[0]) < 257 and int(ip_first_parts[0]) >= 0) and (int(ip_first_parts[1]) < 257 and int(ip_first_parts[1]) >= 0) and (int(ip_first_parts[2]) < 257 and int(ip_first_parts[2]) >= 0) and (int(ip_first_parts[3]) < 257 and int(ip_first_parts[3]) >= 0) and (int(ip_untill) < 257 and int(ip_untill) >= 0):
               reply = True
         except Exception :
            #nothing
            print('.'),
   
   print("Done")   
   return reply

# func Create IP list of range
def func_createIPlist(ip_range):
   print('Creating IP list...'),
   posHyphen = ip_range.find('-')
   ip_first = ip_range[:posHyphen]
   ip_untill = ip_range[posHyphen +1:]
   ip_first_parts = ip_first.split('.')
   ip_list = []
	
   for x in range(int(ip_first_parts[3]), int(ip_untill)+1):
      ip_list.append(str(ip_first_parts[0]) + '.' + str(ip_first_parts[1]) + '.' + str(ip_first_parts[2]) + '.' + str(x))
   print('Done')
   return ip_list

#func Thread-chunks of ip list
def func_createThreadsIPlist(ip_list):
    print('Creating Threads of IP list...')
    ip_threads = []
    ips = 0
    for jj in ip_list :
        ips = ips +1
    chunks = int(math.ceil(float(float(ips)/float(threads))))
    next = 0
    for i in range(chunks):
        ip_threads.append(i)
        ip_threads[next] = []
        for ii in range(threads):
            try:
                if len(ip_list[0]) > 5 :
                    ip_threads[next].append(ip_list[0])
                    ip_list.pop(0)
                else :
                    break
            except:
                break
        next = next +1
    return ip_threads

# func Get files from /data directory
def func_getDataFiles():
   data_files = glob.glob("data/*")
   return data_files

# func fill Text with something
def func_fillText(item, times):
   txt = ""
   i = 0
   while i < int(times) :
      txt += str(item)
      i += 1
   return txt 
	
# func Show Data Files to attack
def func_printDataFileOptions(data_files):
   
   # If no files in default directory
   empty = False
   if data_files == False or len(data_files) == 0:
      empty = True
      	
   # Add files to menu options
   i = 1
   ops = {}
   for f in data_files :
      ops[i] = f
      i += 1
	
   # Add default items to menu options
   ops['e'] = "Exit Program"
	
   # Create Menu
   ln = [] 
   inner_length = 50
   ln.append(" *" + func_fillText("*", inner_length) + "*")
   ln.append(" * " + "Select a file from the data/ directory" + func_fillText(" ", inner_length-38-2) + " *") # inner_length-38-2 = inner_length - text_length - outside spaces
   ln.append(" *" + func_fillText("-", inner_length) + "*")
   
   if empty == True:
      ln.append(" * " + "Data directory is empty" + func_fillText(" ", inner_length-23-2) + " *")
      ln.append(" *" + func_fillText(" ", inner_length) + "*")
   
   for o in ops :
      o_txt = str(o) + " : " + str(ops[o])
   	
      # if text to long for menu
      if len(o_txt) > 45 :
         first = o_txt[:35]
         last = o_txt[-6:]
         o_txt = first + "..." + last
   		
      # file output
      ln.append(" * " + o_txt + func_fillText(" ", inner_length-len(o_txt)-2) + " *")
   	
   ln.append(" *" + func_fillText("*", inner_length) + "*")
	
   txt = "\n"
   for item in ln :
      txt = txt + str(item) + "\n"
	
   # return
   return txt

#def func Find webpage title
def func_titleFilter(page):
    try:
        pageL = page.lower()
        start = pageL.find('<title>') +7
        end = pageL.find('</title>', start)
        if int(start) > 10:
            title = page[start:end]
            if title[0] == '<' :
                title = 'No Title Found'
        else :
            title = 'No Title Found'
    except :
         title = 'No Title Found'
    return title

# func Exit
def func_exit():
   print("Exiting...\n\nThanks for using\nCleveridge IP Spider\n\nCleveridge : https://cleveridge.org /nIP Spider : https://github.com/Cleveridge/cleveridge-ip-spider")





#++ PROGRAM ++#
os.system('clear')

print("************************************************")
print("||             CLEVERIDGE IP SPIDER           ||")
print("************************************************")
print("||  IMPORTANT:                                ||")
print("||  This tool is for ethical testing purpose  ||")
print("||  only.                                     ||")
print("||  Cleveridge and its owners can't be held   ||")
print("||  responsible for misuse by users.          ||")
print("||  Users have to act as permitted by local   ||")
print("||  law rules.                                ||")
print("************************************************")
print("||     Cleveridge - Ethical Hacking Lab       ||")
print("||               cleveridge.org               ||")
print("************************************************\n")
print("Version %s build %s" % (version, build))










"""
ON FIRST RUN : SETTING UP BASIC FILES AND FOLDERS
BEGIN:
"""

#-- Creating default log directory
logdir = "log"
if not os.path.exists(logdir):
   os.makedirs(logdir)
   txt = "Directory 'log/' created"
   print(txt)

""" Every run : create log file """
#-- Creating log file in directory 'log' --#
now = datetime.now()
logfile = str(now.year) + str(format(now.month, '02d')) + str(format(now.day, '02d')) + '_' + str(format(now.hour, '02d')) + str(format(now.minute, '02d')) + str(format(now.second, '02d')) + ".log"
print("Creating log : log/%s" % (logfile)),
logloc = logdir + "/" + logfile
with open(logloc, "w") as mylog:
   os.chmod(logloc, 0o660)
   txt = "Log created by Cleveridge IP Spider - " + version + " build " + build + "\n\n"
   mylog.write(txt)
   func_addToFinalLog(txt)
   print(".... Done")
""" """

#-- Creating default configuration in directory 'cnf' --#
txt = "Checking configuration status"
func_writelog("a", logloc, txt + "\n")
print(txt)


# if no cnf directory -> Create
cnfdir = "cnf"
if not os.path.exists(cnfdir) :
   os.makedirs(cnfdir)
   txt = "Directory 'cnf/' created"
   func_writelog("a", logloc, txt + "\n")
   print(txt)
   

# if no user ip file in cnf -> create
file_userip = cnfdir + "/userip.cnf"
if not os.path.exists(file_userip) :
   with open(file_userip, "w") as myuserip :
      os.chmod(file_userip, 0o660)
      myuserip.write("1.1.1.1")
      txt = "File 'userip.cnf' created in 'cnf/'"
      func_writelog("a", logloc, txt + "\n")
      print(txt)
      

# if default file directory not exist -> create
datadir = 'data'
if not os.path.exists(datadir) :
   os.makedirs(datadir)
   txt = "Directory 'data/' created"
   func_writelog("a", logloc, txt + "\n")
   print(txt)

"""
:END
ON FIRST RUN : SETTING UP BASIC FILES AND FOLDERS
"""







print(" ") # to create a better view of the logs on screen


#-- Register date and time of scan --#
txt = "Tool started : %s/%s/%s - %s:%s:%s" % (now.year, format(now.month, '02d'), format(now.day, '02d'), format(now.hour, '02d'), format(now.minute, '02d'), format(now.second, '02d'))
func_writelog("a", logloc, txt + "\n\n")
func_addToFinalLog(txt)
print(txt)
print(" ")

#-- Verify users IP --#
print("Fill out your machines IP. This is the IP you want to hide!!")
print("If the IP is the same as the default, just hit [Enter]...")
with open(file_userip, 'r') as cont :
   content = cont.read()
   try: input = raw_input # Fix Python 2 >< 3
   except NameError: pass 
   my_ip = input("Your IP [" + content + "] : ") or content
with open(file_userip, 'w') as myuserip : # save new value
   myuserip.write(my_ip[:15]) # save not more then 15 chars
	

#-- Local IP --#
txt = "Local IP : " + [(s.connect(('8.8.8.8', 80)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
func_writelog("a", logloc, txt + "\n")
func_addToFinalLog(txt)
print(txt)

#-- Visible IP --#
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try :
   visible_ip = urllib2.urlopen('https://cleveridge.org/_exchange/open_files/return_ip.php?s=ip_spider', context=ctx).read()
   print('********* %s' % (visible_ip))
except Exception :
   visible_ip = urllib2.urlopen('https://enabledns.com/ip', context=ctx).read()
txt = "Visible IP : " + str(visible_ip)
func_writelog("a", logloc, txt + "\n")
func_addToFinalLog(txt)
print(txt)

#-- if private IP is visible
if visible_ip == my_ip: # if your real ip is visible -> Break up 
   txt = "***********************************************************\n* WARNING !!!                                             *\n*    Are you sure ?                                       *\n*    Your real IP is visible !!!                          *\n*                                                         *\n*    Use a VPN                                            *\n*    or                                                   *\n*    Add 'Socks4 127.0.0.1 9050' to /etc/proxychains.conf *\n*    Start Tor service, then                              *\n*    proxychains ./cl_ssh_scan.py                         *\n***********************************************************"
   func_writelog("a", logloc, txt + "\n")
   func_addToFinalLog(txt)
   print(txt)
   
if False == True:
    pass
else: # CHANGED .... previously : If hidden IP
   
   # Select Method
   print("\n\n *************************************\n * Select a method :                 *\n *************************************\n * h : Scan one host ip              *\n * r : Scan a range of IP's          *" + "\n *************************************")  #\n * f : Scan IP's from file (one/row) *\n *************************************"
   method = input(' * Method : ')
   txt = "Selected Method : "
   func_writelog("a", logloc, txt)
   func_addToFinalLog(txt)
   print(txt),
   
   
   if method == 'h':   
      # Selected Method : (h)ost
      
      txt = "Scan one host IP"
      func_writelog("a", logloc, txt + "\n\n")
      print(txt)
   	
      hostname = input('Victim IP : ')
      func_scanhost(hostname, logloc)
   
   elif method == 'r': 
      # Selected Method : (r)ange
       
      txt = "Scan IP range"
      func_writelog("a", logloc, txt + "\n\n")
      func_addToFinalLog(txt)
      print(txt)
      
      print("Fill out an IP range like 192.168.0.1-25")
      ip_range = input('IP range : ')
      
      # If IP range is valid > execute      
      if(func_checkIPrange(ip_range) != True): # if not valid
         txt = "IP range not valid !! e.g. 192.168.0.1-25"
         func_writelog("a", logloc, txt + "\n")
         print(txt)
      else : # if valid ip range
      	
         # log
         txt = "IP range %s is valid" % (ip_range)
         func_writelog("a", logloc, txt + "\n\n")
         func_addToFinalLog(txt)
         print(txt)
      	
         # creating ip thread list
         ip_range_length = 0
         ip_l = func_createIPlist(ip_range)
         th_l = func_createThreadsIPlist(ip_l)
         
         # run scan for every ip in range
         time_stamp_start = int(time.time())
         thrds = []
         for th in th_l :
             for hostname in th:
                t = threading.Thread(target=func_scanhost, args=(hostname, logloc,))
                thrds.append(t)
                t.start()
         
         # When all threads ended : show results
         for t in thrds:
             t.join()
         time.sleep(5)
         
         print(' ')
         print('Results:')
         print('********')
         #for key, val in enumerate(logresults):   #cacheresult) :
         for num in range(0, 256):
             if num in logresults :
                 txt = logresults[num]   #cacheresult[value]
                 print(txt)
                 func_addToFinalLog(txt)
         
         # Create Final Log
         func_writelog("w", logloc, finallog + "\n\n")
         
         # End of Scan
         time_stamp_end = int(time.time())
         duration = time_stamp_end - time_stamp_start
         txt = 'Scan Ended \nDuration ' + time.strftime('%H hours %M min %S sec', time.gmtime(duration)) + '\n\nLog at ' + logloc
         func_writelog("a", logloc, txt + "\n\n")
         print(txt)
         
         func_exit()
         
             
             
      	
      
   elif method == 'f':
      #Selected Method : (f)ile
       
      txt = "Scan IP's from file"
      func_writelog("a", logloc, txt + "\n\n")
      print(txt)
      
      d_files = func_getDataFiles()
      txt = func_printDataFileOptions(d_files)
      print(txt)[:-1] # to remove the last \n
      
      ip_file = input(" * Select : ")
      
      # Get File contents or Exit
      goon = False
      try:
         val = int(ip_file)
         goon = True
         val  = val -1 # because array keys are options -1
      except Exception :
         print('No file selected')
      
      # if selection is an integer and if selection exists -> execute else exit
      ip_l = []
      if goon == True :
         print(d_files[val])
         try :
            fl = open(d_files[val], 'r')
      		
            txt = "Selected File : " + str(d_files[val])
            func_writelog("a", logloc, txt + "\n")
            print(txt)
      		
            
            for line in fl :
               ip_l.append(line)
               print(' - ' + line)
         except Exception :
            print('Selection not valid')
      else :
         func_exit()
      
      # if ip's in file else exit
      if len(ip_l) > 0 :
         # If valid IP -> run scan
         for hostname in ip_l :
            try :
               socket.inet_aton(hostname)
               func_scanhost(hostname, logloc)
            except socket.error :
               print("Contains an unvalid IP")
      else :
         print("The selected file seems empty")
         func_exit()
   
   else :
      func_exit()
      	
