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
            
            tmpllist = zapi.host.get(
            selectParentTemplates=[
            "templateid"],
            hostids=hostid)

            templatelist = []

            for item in itemlist:
                for key1,val1 in item.items():
                    if key1 == 'parentTemplates':
                        for value in val1:
                            if isinstance(value, dict):
                                for key2,val2 in value.items():
                                    templatelist.append(val2)
            
            output = item_name + "," + item_id + "," + host_template_id + "," + item_error + "," + str(templatelist)
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
            
def createhost(host_name, host_ip, port = '10050'):
    #output = host_name + "," + host_ip + "," + group_id + "," + interfaces + "," + template_id + "," + inventory + "," + str(status) + "," + connect_to + "," + port
    #print output
    # interface needs to be the agents IP public IP address
    # IP and DNS are both required even if we're only using one
    # 
    # if hostgroup.get
    # and if template.get
    groupid = 2
    templateid = 10001
    hostid = zapi.host.create({ 'host': host_name, 'interfaces': [{'type': 1,'main': 1,'useip': 1,'ip': host_ip,'dns': '','port': port}],'groups': [{'groupid': groupid}],'templates' : [{ 'templateid': templateid}] }) ['hostids'][0]
    # hostid = zapi.host.create({ 'name': hostname, 'dns' : hostname,'ip' : hostip,  'port'   : port,'useip' : 0,'groups' : [{ "groupid":gid}], 'templates' : [{ "templateid":tid}]}), 'interfaces' : interfaces



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

#createhost hostname, host IP, group ID, template ID, connect_to 
createhost('CFS-LH-10010', '192.168.1.231')


    
#itemlist = zapi.template.get(output='extend', filter={"hostid": 10106} )
#pp = pprint.PrettyPrinter(indent=4)
#pp.pprint(itemlist)


