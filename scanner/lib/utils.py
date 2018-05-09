#!/usr/bin/env python
# -*- coding:utf-8 -*-

# @Author:Jacky
# @mail:  jackyops@163.com
# @Time:  18-5-8 下午10:33
# @File:  utils.py
import re

def mac_trans(mac):
    '''
    转化mac地址，将传递到mac进行数据格式的转换
    :param mac:
    :return:
    '''
    if mac:
        mac_lst = mac.split("\n")
        mac_res = [item.replace(":",'').replace("000000000000",'').replace("00000000",'') for item in mac_lst]
        mac_str = "_".join(mac_res)
        return mac_str
    else:
        return ""

def sn_trans(sn):
    '''
    转化SN序列号，将传递到SN号进行数据格式的转换
    :param sn:
    :return:
    '''
    if sn:
        sn_res = sn.replace(" ",'')
        return sn_res
    else:
        return ""

def getsysversion(version_lst):
    '''
    提取系统版本
    :param version_list:
    :return:
    '''
    for version_data in version_lst:
        v_data_lst= re.findall("vmware|centos|linux|ubuntu|redhat|\d{1,}\.\d{1,}",version_data,re.IGNORECASE)
        if v_data_lst:
            if len(v_data_lst) > 1:
                v_data = " ".join(v_data_lst)
                break
            else:
                v_data = ""
    return v_data

def machine_type_trans(mt):
    '''
    转化类型，将传递到类型进行数据格式的转换
    :param mt:
    :return:
    '''
    if mt:
        mt_res = mt.replace("\n",'')
        return mt_res
    else:
        return ""