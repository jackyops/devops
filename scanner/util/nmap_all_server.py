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
        # 遍历扫描主机
        for ip in tcp_all_ip:
            if nm[ip]['status']['state'] == 'up':
                host_lst.append(ip)
                for port in port_lst:
                    try:
                        print("Scan ip %s ..... Port %s"%(ip,port))
                        logging.info("Scan ip %s ..... Port %s"%(ip,port))
                        tm = telnetlib.Telnet(host=ip,port=port,timeout=4)
                        tm_res = tm.read_until("\n",timeout=4)
                    except EOFError as e:
                        print(e)



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
