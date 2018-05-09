#!/usr/bin/env python
# -*- coding:utf-8 -*-

# @Author:Jacky
# @mail:  jackyops@163.com
# @Time:  18-5-7 下午11:04
# @File:  login_do.py

import os
import logging
import paramiko
import traceback
logger = logging.getLogger("django")

os.environ["DJANGO_SETTINGS_MODULE"] ='devops.settings'

class J_ssh_do(object):
    def __init__(self,info=""):
        self.whitelst= ["192.168.5.1","192.168.5.99"]
        self.result = {"info":info}

    def pass_do(self,login_info,cmd_lst=""):
        '''
        用户密码方式登录
        :param login_info:用户密码方式登录
        :param cmd_lst:登录机器后，需要执行的命令
        :return:
        '''
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(login_info[0],login_info[1],login_info[2],login_info[3],timeout=3)
            self.result["status"] =  "success"
            for cmd in cmd_lst:
                stdin,stdout,stderr = ssh.exec_command(cmd,timeout=10)
                std_res = stdout.read()
                self.result[cmd] =  std_res.decode()
        except Exception as e:
            print(traceback.print_exc(),login_info)
            # logger.exception("Use passwd ssh login exception:%s,%s"%(e,login_info))
            self.result["status"] = "failed"
            self.result["res"] = str(e)
        return self.result

    def rsa_do(self,login_info,cmd_lst=""):
        '''
        id_rsa密钥登录
        :param login_info: ('192.168.5.10', 22, 'root', '/key/id_rsa','123')
        :param cmd_lst:
        :return:
        '''

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            key = paramiko.RSAKey.from_private_key_file(login_info[3])
            ssh.connect(login_info[0],login_info[1],login_info[2],pkey=key,timeout=2)
            self.result["status"] = "success"
            for cmd in cmd_lst:
                stdin,stdout,stderr = ssh.exec_command(cmd,timeout=10)
                std_res = stdout.read()
                self.result[cmd] = std_res.decode()
        except Exception as e:
            print(traceback.print_exc(),login_info)
            # logger.exception("Use rsa key ssh login exception:%s,%s" % (e, login_info))
            self.result['status'] = "failed"
            self.result['res'] = str(e)
        return self.result

    def dsa_do(self,login_info,cmd_lst=""):
        '''
        id_dsa密钥登录
        :param login_info: ('192.168.5.10', 22, 'root', '/key/id_dsa','123')
        :param cmd_lst:
        :return:
        '''

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            key = paramiko.DSSKey.from_private_key_file(login_info[3])
            ssh.connect(login_info[0],login_info[1],login_info[2],pkey=key,timeout=2)
            self.result["status"] = "success"
            for cmd in cmd_lst:
                stdin,stdout,stderr = ssh.exec_command(cmd,timeout=10)
                std_res = stdout.read()
                self.result[cmd] = std_res.decode()
        except Exception as e:
            print(traceback.print_exc(),login_info)
            # logger.exception("Use dsa key ssh login exception:%s,%s" % (e, login_info))
            self.result['status'] = "failed"
        return self.result

    def zkteco_rsa_do(self,login_info,cmd_lst=""):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            key = paramiko.RSAKey.from_private_key_file(login_info[3],login_info[4])
            ssh.connect(login_info[0], int(login_info[1]), login_info[2], pkey=key, timeout=2)
            self.result["status"] = "success"
            for cmd in cmd_lst:
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
                std_res = stdout.read()
                self.result[cmd] = std_res
        except Exception as e:
            print
            traceback.print_exc()
            logger.exception("Use rsa key and Non-root user ssh login exception:%s,%s" % (e, login_info))
            self.result["status"] = "failed"
        return self.result



