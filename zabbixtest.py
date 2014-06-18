#!/usr/bin/env python

from pyzabbix import ZabbixAPI
import socket
from getpass import getpass
import ConfigParser




def CheckConnection():
    try:
            config = ConfigParser.ConfigParser()
            config.read("zabbixmagic.ini")
            ZABBIX_SERVER = config.get("zabbixserver", "server")
            ZABBIX_USER = config.get("zabbixserver", "user")
            ZABBIX_PASS = config.get("zabbixserver", "password")
            zapi = ZabbixAPI(ZABBIX_SERVER)
            zapi.login(ZABBIX_USER, ZABBIX_PASS)
    except:
        print "Could'n connect to zabbix. Please check if URL " + ZABBIX_SERVER + " is avaiable"
        exit(1)


CheckConnection()
   

#host_name = 'CFS-LH-10009'
#hosts = zapi.host.get(filter={"host": host_name})
#if hosts:
#    host_id = hosts[0]["hostid"]
#    print("Found host id {0}".format(host_id))
#else:
#    print("No hosts found")



#Get a hostlist
hostlist = zapi.host.get(output='extend')
#pp = pprint.PrettyPrinter(indent=4)
#pp.pprint(hostlist)

for host in hostlist:
    host_id = host['hostid']
    host_name = host['name']
    
    
    #itemlist = zapi.item.get(output='extend', filter={"hostid": 10106} )
    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(itemlist)
    #Templateid is "0" for non-templated, something else for templated item
    #for i in itemlist:
    #    print i
        #if i['templateid'] == "0":
        #Commented to avoid colateral damage. Change it to delete items
        #zapi.item.delete(i['itemid'])
        #print i['name'], " - deleted"
    #else:
    #    print i['name'], " - preserved"
