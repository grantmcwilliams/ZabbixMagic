#!/usr/bin/env python

#Bugs

import struct, socket
import getopt, sys, os
import subprocess
import ast
import re
from pyzabbix import ZabbixAPI
import ConfigParser

def ip2int(ip):
    val = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
    return val(ip)

def int2ip(num):
    val = lambda n: socket.inet_ntoa(struct.pack('!I', n))
    return val(num)

def valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError: 
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True

def valid_patt(patt,item):
    match = patt.search(item)
    if match:
        return True
    else:
        return False

def checkip(seqip, iplist):
    for ip in iplist:
        if ip == seqip:
            return True
            
def checknetmask(netmask):
    if netmask >= 1 and netmask <= 32:
        return True
    else:
        return False
         
       
def listitems(itemtype):        
    if itemtype in 'hosts':
        itemlist = zapi.host.get(output='extend')
        for item in itemlist:
            item_id = item['hostid']
            item_name = item['name']
            item_status = item['status']
            item_error = item['error']
            host_template_id = item['templateid']
                
            output = item_name + "," + item_id + "," + host_template_id + "," + item_error
            print output 
            
    if itemtype in 'templates':
        itemlist = zapi.template.get(output='extend')
        for item in itemlist:
            item_id = item['templateid']
            item_name = item['name']
            output = item_name + "," + item_id 
            print output 
            
    if itemtype in 'hostgroups':
        itemlist = zapi.template.get(output='extend')
        for item in itemlist:
            item_id = item['templateid']
            item_name = item['name']
            output = item_name + "," + item_id 
            print output 

        
def createhost(name, template):
    patt = re.compile(r'CFS-(LH|VLH|SC|CE|PE|VE|BE)-[0-9]{5,6}') 
    if valid_patt(patt,name):
        name = name
    
    patt = re.compile(r'(LH|VLH|SC|CE|PE|VE|BE)') 
    if valid_patt(patt,name):
        name = "CFS-%s-%s" % (name,incrementasset(name))

    grouplist = listgroup('verbose')
    if not searchlist(group, grouplist):
        print "Please enter a valid Group"
        sys.exit(2)

    clientip = incrementipgroup(group)
    if not clientip:
        print "Error: Unable to increment IP"
        sys.exit(2)

    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key prop_autologin --value true UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()

    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key conn_group --value ' + group +' UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key pvt_password_digest --value 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key conn_ip --value ' + clientip +' UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    return name

def deletehost(name):
    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' UserPropDelAll'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()


def usage():
    progname =  os.path.basename(sys.argv[0])
    print ""
    print "%s arguments:" % progname
    print "-h, --help                                   Show this help message and exit"
    print "-l, --list hosts                             List hosts"
    print "-l, --list templates                         List templates" 
    print "-l, --list hostgroups                        List templates" 
    print "-c  --create host -n <name>                  Create new host"
    print "-d, --delete host -n <name>                  Delete client"
    print ""
    print "Examples:"
    print "Create a new client:"
    print "     %s --create=client --group=engines" % progname
    print "Delete a client:"
    print "     %s --delete=host1" % progname
    print ""

def loginzabbix():
    try:
        config = ConfigParser.ConfigParser()
        config.read("zabbixmagic.ini")
        ZABBIX_SERVER = config.get("zabbixserver", "server")
        ZABBIX_USER = config.get("zabbixserver", "user")
        ZABBIX_PASS = config.get("zabbixserver", "password")
        global zapi
        zapi = ZabbixAPI(ZABBIX_SERVER)
        zapi.login(ZABBIX_USER, ZABBIX_PASS)
    except:
        print "Could'n connect to zabbix. Please check if URL " + ZABBIX_SERVER + " is available"
        exit(1)


def main():
    network = None
    platform = None
    name = None
    attribute = None
    verbose = False

    loginzabbix()
    
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "hl:c:d:", ["help","list=","create=","name=","delete="])
        if not opts:
            usage()
            sys.exit(2)
    except getopt.GetoptError as err:
        print(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-l","--list"):
            itemtype = arg
            operation = 'list'
        elif opt in ("-c","--create"):
            itemtype = arg
            operation = 'create'
        elif opt in ("-n","--name"):
            name = arg
        elif opt in ("-d","--delete"):
            option = arg
            operation = 'delete'
        else:
            operation = 'usage'
            usage()
            sys.exit()
    
    if operation in 'list':
        listitems(itemtype)
        

   

        
if __name__ == "__main__":
    main()

