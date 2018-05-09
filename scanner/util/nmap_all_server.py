#!/usr/bin/env python
# -*- coding:utf-8 -*-

# @Author:Jacky
# @mail:  jackyops@163.com
# @Time:  18-5-5 上午9:52
# @File:  nmap_all_server.py

import os
import re
import telnetlib

PROJECT_ROOT = os.path.realpath(os.path.dirname(__file__))
from pysnmp.entity.rfc3413.oneliner import cmdgen

import nmap
import time

import logging
logger = logging.getLogger("django")

from scanner.lib.login_do import J_ssh_do
from scanner.lib.utils import mac_trans,sn_trans,machine_type_trans,getsysversion



def snmp_begin(nmap_type,ports,password_list,key_file,syscmd_list,black_list,s_emails):
    '''
    执行系统主机扫描
    :param nmap_type:
    :param ports:
    :param password_list:
    :param imoocc_key_file:
    :param imoocc_key_file:
    :param syscmd_list:
    :param black_list:
    :param s_emails:
    :return:
    '''

    if nmap_type is None: return False

    nmap_net = '%s.0/24' %nmap_type
    nm_item = NmapDev(black_list)
    sship_lst,host_lst,unkown_lst = nm_item.nmap_sship(ports,nmap_net)
    canlogin_lst,notlogin_lst=nm_item.try_login(sship_lst,password_list,syscmd_list)
    #print("canlogin_lst:%s --- notlogin_lst:%s " %(canlogin_lst,notlogin_lst))
    key_login_lst,key_not_login_lst = nm_item.try_key_login(notlogin_lst,key_file,syscmd_list)

    return canlogin_lst,notlogin_lst


class NmapDev(object):
    '''
    扫描类：扫描获取指定网段主机等对象信息
    '''

    def __init__(self,black_list=[]):
        self.black_list = black_list
        self.can_login_lst = {}
        self.not_login_lst = {}
        self.can_key_login_lst = {}
        self.key_not_login_lst = {}

    def nmap_allip(self,nmap_net):
        '''
        扫描网段中存活主机
        '''
        nm = nmap.PortScanner()
        nm.scan(hosts=nmap_net,arguments='-n -sP -PE')
        # nm.scan(hosts=nmap_net, arguments='-n -PA -PS')
        hostlist = nm.all_hosts()
        return hostlist

    def nmap_sship(self,ports,nmap_net):
        '''
        扫描主机指定ssh端口是否开通ssh端口
        :param ports:
        :param port_list:
        :param unkown_list:
        :param nmap_net:
        :return:
        '''
        ports = ports
        port_lst = ports.split(',')
        nm = nmap.PortScanner()
        ssh_info = {}
        unkown_lst = []

        # 调用扫描方法，参数指定扫描主机hosts，nmap扫描命令行参数arguments
        nm.scan(hosts=nmap_net,arguments='-n -sP -PE')
        tcp_all_ip = nm.all_hosts()
        host_lst = []
        print("tcp_all_ip ---->",tcp_all_ip)
        # 遍历扫描主机
        for ip in tcp_all_ip:
            if nm[ip]['status']['state'] == 'up':
                host_lst.append(ip)
                for port in port_lst:
                    try:
                        print("Scan ip %s ..... Port %s"%(ip,port))
                        logging.info("Scan ip %s ..... Port %s"%(ip,port))
                        tm = telnetlib.Telnet(host=ip,port=port,timeout=4)
                        tm_res = tm.read_until("\n".encode(),timeout=4)
                        print("---tm_res-->",tm_res)
                        if tm_res:
                            if re.search("ssh",tm_res.decode().lower()):
                                if ip not in self.black_list:
                                    ssh_info[ip] = port
                                    connet = "IP:%s Port:%s Server:%s"%(ip,port,tm_res.lower())
                                    logger.info("IP:%s Port:%s Server:%s"%(ip,port,tm_res.lower()))
                                    print("IP:%s Port:%s Server:%s"%(ip,port,tm_res.lower()))
                                else:
                                    if ip not in unkown_lst and ip not in ssh_info.keys():
                                        unkown_lst.append(ip)
                                        logger.info("Telnet not ssh server:%s,%s,%s" %(ip,port,tm_res))
                                    print("Open....",ip,port)
                        else:
                            if ip not in unkown_lst and ip not in ssh_info.keys():
                                unkown_lst.append(ip)
                                logger.info("Telnet no data:%s,%s"%(ip,port))
                            print("Open....",ip,port)
                    except EOFError as e:
                        if ip not in unkown_lst and ip not in ssh_info.keys():
                            unkown_lst.append(ip)
                            unkown_lst.append(ip)
                        #logger.exception("Telnet port EOFError:%s,%s,%s" % (ip, port, e))
                        print("Open...", ip, port)
                    except Exception as e:
                        if ip not in unkown_lst and ip not in ssh_info.keys():
                            unkown_lst.append(ip)
                        #logger.exception("Telnet port Exception:%s,%s,%s" % (ip, port, e))
                        print("error...", ip, port, e)
        return ssh_info,host_lst,list(set(unkown_lst))

    def try_login(self,sship_lst,password_lst,syscmd_lst):
        '''
        尝试ssh用户密码登录，获取机器基本信息
        :param sship_lst:
        :param password_lst:
        :param syscmd_lst:
        :return:
        '''
        password_lst = password_lst
        syscmd_lst = syscmd_lst
        if isinstance(sship_lst,dict):
            ssh_tuple_list = [(ip,port) for ip,port in sship_lst.items()]
        elif isinstance(sship_lst,list):
            ssh_tuple_list = sship_lst
        for ip,port in ssh_tuple_list:
            system_info = ""
            for password in password_lst:
                if ip not in self.can_login_lst.keys():
                    login_info = (ip,int(port),'root',password)
                    doobj = J_ssh_do(login_info)
                    res = doobj.pass_do(login_info,syscmd_lst)
                    if res["status"] == "success":
                        if ip in self.not_login_lst:
                            self.not_login_lst.pop(ip)
                        sys_hostname = res["hostname"]
                        sys_mac = mac_trans(res["cat /sys/class/net/[^vtlsb]*/address||esxcfg-vmknic -l|awk '{print $8}'|grep ':'"])
                        sys_sn = sn_trans(res["dmidecode -s system-serial-number"])
                        system_info = getsysversion([res["cat /etc/issue"],res["cat /etc/redhat-release"]])
                        machine_type = machine_type_trans(res["dmidecode -s system-manufacturer"] + res["dmidecode -s system-product-name"])
                        print("ssh login and exec command: %s"%(res))
                        # logger.info("ssh login and exec command:%s",res)
                        self.can_login_lst[ip] = (port,password,'root',system_info,sys_hostname,sys_mac,sys_sn,machine_type)
                    elif res["status"] == "failed" and re.search(r"reading SSH protocol banner",res["res"]):
                        print("IP:%s Connection closed by remote host,Sleep 60 (s).................. " % ip, res)
                        time.sleep(60)
                    else:
                        if ip not in self.not_login_lst.keys() and ip not in self.can_login_lst.keys():
                            self.not_login_lst[ip] = port
        return self.can_login_lst,self.not_login_lst

    def try_key_login(self,sship_lst,allkeyfile,syscmd_list):
        '''
         尝试ssh秘钥登录，获取机器基本信息
        :param sship_lst:
        :param allkeyfile:
        :param syscmd_list:
        :return:
        '''

        for ip,port in sship_lst.items():
            print("try key login ...",ip,port)
            # logger.info("Try ssh key login : %s,%s" % (ip, port))
            keyfile = allkeyfile[0]
            if ip not in self.can_login_lst.keys():
                logger.info("Try ssh idrsa key : %s,%s,%s" % (ip, port, keyfile))
                print('try idrsakey....', ip, port, keyfile)
                login_info = (ip,int(port),'root',keyfile)
                doobj = J_ssh_do(login_info)
                res = doobj.rsa_do(login_info,syscmd_list)
                if res["status"] == "success":
                    sys_hostname = res["hostname"]
                    system_info = getsysversion([res["cat /etc/issue"], res["cat /etc/redhat-release"]])
                    sys_mac = mac_trans(res["cat /sys/class/net/[^vtlsb]*/address||esxcfg-vmknic -l|awk '{print $8}'|grep ':'"])
                    sys_sn = sn_trans(res["dmidecode -s system-serial-number"])
                    machine_type = machine_type_trans(res["dmidecode -s system-manufacturer"] + res["dmidecode -s system-product-name"])
                    self.can_key_login_lst[ip] = (port,keyfile,"root","",1,system_info,sys_hostname,sys_mac,sys_sn,machine_type)
                if res["status"] == "failed":
                    keyfile = allkeyfile[1]
                    logger.info("try iddsa login...%s,%s,%s" % (ip, port, keyfile))
                    print("try iddsa login...", ip, port, keyfile)
                    login_info = (ip,port,'root',keyfile)
                    doobj = J_ssh_do(login_info)
                    res = doobj.dsa_do(login_info,syscmd_list)
                    if res["status"] == "success":
                        sys_hostname = res["hostname"]
                        system_info = getsysversion([res["cat /etc/issue"], res["cat /etc/redhat-release"]])
                        sys_mac = mac_trans(res["cat /sys/class/net/[^vtlsb]*/address||esxcfg-vmknic -l|awk '{print $8}'|grep ':'"])
                        sys_sn = sn_trans(res["dmidecode -s system-serial-number"])
                        machine_type = machine_type_trans(res["dmidecode -s system-manufacturer"] + res["dmidecode -s system-product-name"])
                        if ip in self.key_not_login_lst:self.key_not_login_lst.pop(ip)
                        self.can_key_login_lst[ip] = (port,keyfile,"root","",2,system_info,sys_hostname,sys_mac,sys_sn,machine_type)
                    else:
                        keyfile = allkeyfile[2]
                        # logger.info("try Non-root idrsa login:%s,%s" % (ip, port))
                        print("try Non-root idrsa login...",ip,port)
                        password = '123456'
                        login_info = (ip,port,'zkteco',keyfile,password)
                        doobj = J_ssh_do(login_info)
                        res = doobj.zkteco_rsa_do(login_info,syscmd_list)






                            keyfile = allkeyfile[2]
                            logger.info("try Non-root idrsa login:%s,%s" % (ip, port))
                            print
                            "try Non-root idrsa login...", ip, port
                            password = '0koooAdmin'
                            login_info = (ip, port, 'imoocc', keyfile, password)
                            doobj = J_ssh_do(login_info)
                            res = doobj.imoocc_rsa_do(login_info, syscmd_list)
                            if res["status"] == "success":
                                sys_hostname = res["hostname"]
                                sys_mac = mac_trans(res[
                                                        "cat /sys/class/net/[^vtlsb]*/address||esxcfg-vmknic -l|awk '{print $8}'|grep ':'"])
                                system_info = getsysversion([res["cat /etc/issue"], res["cat /etc/redhat-release"]])
                                sys_sn = sn_trans(res["dmidecode -s system-serial-number"])
                                machine_type = machine_type_trans(
                                    res["dmidecode -s system-manufacturer"] + res["dmidecode -s system-product-name"])
                                if self.key_not_login_lst.has_key(ip): self.key_not_login_lst.pop(ip)
                                self.can_key_login_lst[ip] = (
                                port, keyfile, "root", "", 3, system_info, sys_hostname, sys_mac, sys_sn, machine_type)
                            else:
                                if ip not in self.key_not_login_lst.keys() and ip not in self.can_key_login_lst.keys():
                                    self.key_not_login_lst[ip] = (port, keyfile)
            return self.can_key_login_lst, self.key_not_login_lst


class NmapNet(object):
    def __init__(self,sysname_oid="",sn_oid="",community=""):
        self.community = community
        self.sysname_oid = sysname_oid
        self.sn_oid = sn_oid

    def sysname_query(self,ip,sn_old):
        try:
            cg = cmdgen.CommandGenerator()
            errorIndication,errorStatus,errorIndex,varBinds = cg.getCmd(
                cmdgen.CommunityData('server',self.community,1),
                cmdgen.UdpTransportTarget((ip,161)),
                '%s'%sn_old
            )
            result = str(varBinds[0][1] if varBinds[0][1] else "")
            logger.info("try nmap net device:%s"%result)

        except Exception as e:
            logger.exception("try nmap net device exception:%s" % e)
            result = None
        return result



    def query(self,ip):
        '''
        查询交换机的snmp相关信息
        :return:'
        '''

        result = []
        result.append(self.sysname_query(ip))
        return result


