#!/usr/bin/env python

#Bugs

import struct, socket
import getopt, sys, os
import subprocess
import ast
import re
from pyzabbix import ZabbixAPI
import ConfigParser
import pprint

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
        if itemlist:
            for item in itemlist:
                item_id = item['hostid']
                item_name = item['name']
                item_status = item['status']
                item_error = item['error']
                templatelist = []

                #Get templates
                tmpllist = zapi.host.get(selectParentTemplates=["templateid"],hostids=item_id)
                templatelist[:] = []
                for tmpl in tmpllist:
                    for key1,val1 in tmpl.items():
                        if key1 == 'parentTemplates':
                            for value in val1:
                                if isinstance(value, dict):
                                    for key2,val2 in value.items():
                                        templatelist.append(val2)
                templates = ",".join(templatelist)
                if not templates:
                    templates = "NA"
                
                #Get interfaces
                ifacelist = zapi.hostinterface.get(output='extend', filter={"hostid": item_id,"main": 1} )
                for iface in ifacelist:
                    iface_ip = iface['ip']
                    iface_use_ip = iface['useip']
                    iface_type = iface['type'] 
                    iface_ns = iface['dns']
       
                #Map iface_type number to text and assign to iface_name
                iface_name = {'1': 'Agent',
                '2': 'SNMP',
                '3': 'IPMI',
                '4': 'JMX'
                }.get(iface_type, '')
      
      
                if iface_use_ip == '0':
                    host_name = iface_ns
                    host_ns_type = 'DNS'
                elif iface_use_ip == '1':
                    host_name = iface_ip
                    host_ns_type = 'IP'
            
                output = item_name + "," + item_id + ",[" + templates + "]," + iface_ip + "," + iface_name + "," + host_ns_type + "," + host_name
                print output 
        else:
            print "No " + itemtype 

            
    if itemtype in 'templates':
        itemlist = zapi.template.get(output='extend')
        if itemlist:
            for item in itemlist:
                item_id = item['templateid']
                item_name = item['name']
                output = item_name + "," + item_id 
                print output 
        else:
            print "No " + itemtype            
            
    if itemtype in 'hostgroups':
        itemlist = zapi.hostgroup.get(output='extend')
        if itemlist:
            for item in itemlist:
                item_name = item['name']
                item_id = item['groupid']
                output = item_name + "," + item_id
                print output 
        else:
            print "No " + itemtype

    if itemtype in 'graphs':
        itemlist = zapi.graph.get(output='extend',)
        if itemlist:
            for item in itemlist:
                print item
                item_name = item['name']
                item_id = item['graphid']
                graph_type = item['graphtype']
                template_id = item['templateid']
                output = item_name + "," + item_id + "," + graph_type + "," + template_id
                print output 
        else:
            print "No " + itemtype
            
    if itemtype in 'interfaces':
        itemlist = zapi.graph.get(output='extend')
        if itemlist:
            for item in itemlist:
                item_name = item['name']
                graph_id = item['graphid']
                template_id = item['templateid']
                output = item_name + "," + graph_id + "," + template_id
                print output 
        else:
            print "No " + itemtype

    if itemtype in 'applications':
        itemlist = zapi.application.get(output='extend')
        if itemlist:
            for item in itemlist:
                application_id = item['applicationid']
                item_name = item['name']
                host_id = item['hostid']
                output = item_name + "," + application_id + "," + host_id 
                print output 
        else:
            print "No " + itemtype

    if itemtype in 'alerts':
        itemlist = zapi.alert.get(output='extend')
        if itemlist:
            for item in itemlist:
                alert_id = item['alertid']
                action_id = item['actionid']
                user_id = item['userid']
                alert_clock = item['clock']
                alert_subject = item['subject']
                alert_message = item['message']
                alert_status = item['status']
                alert_retries = item['retries']
        
                output = alert_id + "," + action_id + "," + user_id + "," + alert_clock + "," + alert_subject + "," + alert_message + "," + alert_status + "," + alert_retries
                print output 
        else:
            print "No " + itemtype
            
    if itemtype in 'triggers':
        itemlist = zapi.trigger.get(output='extend',selectFunctions='extend')
        if itemlist:
            for item in itemlist:
                trigger_func_list = item['functions']
                trigger_id = item['triggerid']
                trigger_exp = item['expression']
                trigger_desc = item['description']
                trigger_status = item['status']
                
                #funclist = []
                #for func in trigger_func_list:
                #    for key1,val1 in func.items():
                #        if key1 == 'itemid':
                #            funclist.append(val1)
                #item_id = ",".join(funclist)
                #if not item_id:
                #    item_id = "NA"

                #    if hostlist:
                #        host_name = item['name']
                #    else:
                #        host_name = "NA"
                    
                
        
                output = trigger_id + "," + trigger_exp + "," + trigger_desc + "," + trigger_status
                print output
        else:
            print "No " + itemtype
        
def testreq(request):  
        output = getattr(zapi, 'do_request')(request)
        pp.pprint(output)
        
            
def createhost(host_name, host_ip, port_num, group, template):

    group_id = None
    template_id = None

    # interface needs to be the agents IP public IP address
    # IP and DNS are both required even if we're only using one
 
    if group and group.isdigit():
        group_id = int(group)
    else: 
        itemlist = zapi.hostgroup.get(output='extend', filter={"name": group} )
        for item in itemlist:
            group_id = int(item['groupid'])
    
    if not group_id:
        print "Error! Invalid group"
        return 1
    
    if template and template.isdigit():
        template_id = int(template)
    else: 
        itemlist = zapi.template.get(output='extend', filter={"name": template} )
        for item in itemlist:
            template_id = int(item['templateid'])
    
    if not template_id:
        print "Error! Invalid template"
        return 1
    
    
    if zapi.host.get(output='extend', filter={"host": host_name} ):
        print "Host " + host_name + " already exists"
        return 1
      
    if not zapi.template.get(output='extend', filter={"templateids": template_id} ):
        print "Template " + template_id + " does not exist"
        return 1

    if not zapi.hostgroup.get(output='extend', filter={"groupid": group_id} ):
        print "Group " + group_id + " does not exist"
        return 1
    
    hostid = zapi.host.create({ 'host': host_name, 'interfaces': [{'type': 1,'main': 1,'useip': 1,'ip': host_ip,'dns': '','port': port_num}],'groups': [{'groupid': group_id}],'templates' : [{ 'templateid': template_id}] }) ['hostids'][0]



def deletehost(hostid):
    print hostid + " deleted"



def usage():
    progname =  os.path.basename(sys.argv[0])
    print ""
    print "%s arguments:" % progname
    print "-h, --help                                   Show this help message and exit"
    print "-l, --list hosts                             List host,hostid,[templates],ip address,interface type"
    print "-l, --list templates                         List template name, template id" 
    print "-l, --list hostgroups                        List group name, group id"  
    print "-l, --list graphs                            List graph name, graph id, graph type, template id"
    print "-l, --list interfaces                        List interface name, graph id, template id" 
    print "-l, --list applications                      List application name, application id, host id" 
    print "-l, --list alerts                            List alert id, action id, user id, alert clock, alert subject"
    print "                                             alert message, alert status, alert retries" 
    print "-l, --list triggers                          List trigger id, expression, description, status" 
    print "-t, --testreq <zabbix method eg. host.get    Test request - parameters are not supported" 
    print "-c  --create host -n <name> -i <ip> "
    print "             -g <groupid|groupname>" 
    print "             -t <templateid|templatename>    Create new host with name, ip address, group id or name and template id or name"
    print "-d, --delete host -n <name>                  Delete client"
    print ""
    print "Examples:"
    print "Create a new host using default group and template:"
    print "     %s --create host -n testhost -i 192.168.0.100" % progname
    print "Create a new host using group and template ids:"
    print "     %s --create host -n testhost -g 7 -t 10001 -i 192.168.0.100" % progname
    print "Create a new host using group and template names"
    print "     %s -c host -n testhost -g 'Hypervisors' -t 'Template OS Linux' -i 192.168.0.100" % progname
    print "Delete a client:"
    print "     %s --delete host -n testhost" % progname
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
    params = None
    item_type = None
    request = None
    operation = None
    
    host_name = None
    host_id = None
    host_ip = None
    group_id = None
    port_num='10050'
    group='2'
    template='10001'

    loginzabbix()
    
    global pp
    pp = pprint.PrettyPrinter(indent=1)
    
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "hl:r:c:d:n:g:p:i:t:", ["help","list=","req=","create=","delete=","name=","group=","port=","ip=","template="])
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
            item_type = arg
            operation = 'list'
        elif opt in ("-r","--req"):
            request = arg
            operation = 'testreq'
        elif opt in ("-c","--create"):
            operation = 'create'
        elif opt in ("-d","--delete"):
            host_id = arg
            operation = 'delete'
        elif opt in ("-n","--name"):
            host_name = arg
        elif opt in ("-g","--group"):
            group = arg
        elif opt in ("-p","--port"):
            port_num = arg
        elif opt in ("-i","--ip"):
            host_ip = arg
        elif opt in ("-t","--template"):
            template = arg
        else:
            operation = 'usage'
            usage()
            sys.exit()
    
    if operation in 'list':
        listitems(item_type)
        
    if operation in 'testreq':
        testreq(request)
    
    if operation in 'create':
        if not host_name:
            print "Host name required"
            return 1
        if not host_ip:
            print "IP required"
            return 1
            
        createhost(host_name, host_ip, port_num, group, template)
           
           
if __name__ == "__main__":
    main()

