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
                
            output = item_name + "," + item_id + "," + host_template_id 
            print output 
            
    if itemtype in 'templates':
        itemlist = zapi.template.get(output='extend')
        for item in itemlist:
            item_id = item['templateid']
            item_name = item['name']
            output = item_name + "," + item_id 
            print output 
            
    if itemtype in 'hostgroups':
        itemlist = zapi.hostgroup.get(output='extend')
        for item in itemlist:
            item_name = item['name']
            item_id = item['groupid']
            output = item_name + "," + item_id
            print output 

    if itemtype in 'graphs':
        itemlist = zapi.graph.get(output='extend')
        for item in itemlist:
            item_name = item['name']
            item_id = item['groupid']
            output = item_name + "," + item_id 
            print output 
            
    if itemtype in 'interfaces':
        itemlist = zapi.graph.get(output='extend')
        for item in itemlist:
            item_name = item['name']
            output = item_name 
            print output 

        
def createhost(hostname, hostip, groupid, interfaces, templateid, inventory, status, connectto, port = '10050'):
    output = hostname + "," + hostip + "," + groupid + "," + interfaces + "," + templateid + "," + inventory + "," + str(status) + "," + connectto + "," + port
    print output
    # if hostgroup.get
    # and if template.get
    hostid = zapi.host.create({ 'name': hostname, 'dns' : hostname,'ip' : hostip,'groups': [{"groupid":groupid}] })['hostids'][0]
    # hostid = zapi.host.create({ 'name': hostname, 'dns' : hostname,'ip' : hostip,  'port'   : port,'useip' : 0,'groups' : [{ "groupid":gid}], 'templates' : [{ "templateid":tid}]}), 'interfaces' : interfaces
    

def deletehost(hostid):
    print hostid + " deleted"



def usage():
    progname =  os.path.basename(sys.argv[0])
    print ""
    print "%s arguments:" % progname
    print "-h, --help                                   Show this help message and exit"
    print "-l, --list hosts                             List hosts"
    print "-l, --list templates                         List templates" 
    print "-l, --list hostgroups                        List templates" 
    print "-l, --list graphs                            List graphs" 
    print "-l, --list interfaces                        List interfaces" 
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

