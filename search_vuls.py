#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2022/3/28
# @Author  : starnight_cyber
# @Github  : https://github.com/starnightcyber
# @Software: PyCharm
# @File    : search_vuls.py

import datetime
from queue import Queue
from multiprocessing import Pool
import requests
import ssl
import time
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
from prettytable import PrettyTable

# Do not support ssl and disable warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context
timestamp = time.strftime("%Y-%m-%d", time.localtime(time.time()))

headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.83 Safari/537.36'
}

task_queue = Queue()
process_num = 10
services_info = []
total_tasks = []
cve_obj_list = []           # cve obj-s fill with detailed information


class CveObject:
    cve_no = ''                     # 漏洞编号
    cve_nvd_url = ''                # 漏洞nvd url链接地址
    cve_description = ''            # 漏洞描述
    cve_level = ''                  # 威胁等级
    cve_score = ''                  # 威胁评分
    cve_cna = ''                    # 漏洞分配的机构
    def show(self):
        """
        Show basic vul information
        :return: None
        """
        print('----------------------------------')
        print('编号：', self.cve_no)
        print('漏洞描述：', self.cve_description)
        print('漏洞等级：', self.cve_level)
        print('漏洞评分：', self.cve_score)
        print('\n\n')


def worker(cve, index):
    """
    Fetch detailed information by search cve to fill cve_obj that can be fetch from NVD
    :param cve: cve no
    :param cve_obj: cve object to fill
    :return: None
    """
    cve_obj = CveObject()
    cve_obj.cve_no = cve

    nvd_url = 'https://nvd.nist.gov/vuln/detail/'
    url = '{}{}'.format(nvd_url, cve)
    print('[{}] fetch ... {}'.format(index, url))

    cve_obj.cve_nvd_url = url
    try:
        resp = requests.get(url=url, headers=headers, timeout=30, verify=False)
        if resp.status_code == 200:
            content = resp.text
            # print('content => {}'.format(content))
            description = re.findall('<p data-testid="vuln-description">(.*).</p>?', content)
            cve_obj.cve_description = description[0]
            # print('cve_obj.cve_description => {}'.format(cve_obj.cve_description))

            soup = BeautifulSoup(content, "html.parser")
            severity = soup.find('a', id="Cvss3NistCalculatorAnchor").get_text()
            score, cve_level = severity.split(' ')
            cve_obj.cve_score = score
            cve_obj.cve_level = cve_level
            # print(score, cve_level)
    except:
        print('v3 not scored, switch to v2...')
        severity = soup.find('a', id="Cvss2CalculatorAnchor").get_text()
        score, cve_level = severity.split(' ')
        cve_obj.cve_score = score
        cve_obj.cve_level = cve_level
        # print(score, cve_level)
    finally:
        return cve_obj
    pass


def setcallback(cve_obj):
    if cve_obj:
        cve_obj_list.append(cve_obj)


def run_engine():
    pool = Pool(process_num)  # 创建进程池
    index = 0
    while not task_queue.empty():
        index += 1
        task = task_queue.get(timeout=1.0)
        pool.apply_async(worker, args=(task, index), callback=setcallback)
    pool.close()
    pool.join()


def search_vuls(software):
    url = 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={}'.format(software)
    print('[*] checking {} ...'.format(url))
    try:
        resp = requests.get(url=url, headers=headers, timeout=10, verify=False)
        if resp.status_code == 200:
            tmp = re.findall('/cgi-bin/cvename.cgi\?name=(.*)?">', resp.text)
            print('[+] => {}'.format(tmp))
            for cve in tmp:
                task_queue.put(cve)
            print('[*] task qsize => {}'.format(task_queue.qsize()))
    except Exception as e:
        print(str(e))
        pass
    finally:
        pass


def pretty_print():
    global cve_obj_list
    t = PrettyTable(['No.', 'CVE', 'Score', 'Level', 'URL'])
    index = 0
    for cve_obj in cve_obj_list:
        index += 1
        row = [index, cve_obj.cve_no, cve_obj.cve_score, cve_obj.cve_level, cve_obj.cve_nvd_url]
        t.add_row(row)
    print(t)


def main():
    # tips
    software = input('please input which sofware you want to search vuls ... \n\r=> ')
    # search vuls
    search_vuls(software)
    # parallel scan engine
    run_engine()
    # pretty print
    pretty_print()


if __name__ == '__main__':
    start = datetime.datetime.now()
    main()
    end = datetime.datetime.now()
    spend_time = (end - start).seconds
    msg = 'It costs {} seconds to run the task'.format(spend_time)
    print(msg)
