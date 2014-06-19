#!/usr/bin/env python

from pyzabbix import ZabbixAPI
import socket
from getpass import getpass
import ConfigParser
import pprint
        
       
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

def createhost(hostname,hostip,groupid,interfaces,templateid,inventory,status):
    output = hostname + "," + hostip + "," + groupid + "," + interfaces + "," + templateid + "," + inventory + "," + str(status)
    print output

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

loginzabbix()

createhost('examplehost', '192.168.1.100','Lightgroup','eth0','lighttmpl','inventory',0)

    
#itemlist = zapi.template.get(output='extend', filter={"hostid": 10106} )
#pp = pprint.PrettyPrinter(indent=4)
#pp.pprint(itemlist)


