#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import re
import math
from bs4 import  BeautifulSoup


cve_all = []                # cve no-s fetched from nvd
cve_obj = {}

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0'
}

# 漏洞等级对应
level_dict = {
    'CRITICAL': '严重',
    'HIGH': '高',
    'MEDIUM': '中',
    'LOW': '低'
}


def fetch_all_cves(producer, software, banner):
    global cve_all
    cve_all = []

    url = 'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=' \
          'cpe:/a:{}:{}:{}'.format(producer, software, banner)
    print(url)

    # to get cve number
    try:
        response = requests.get(url, timeout=60, headers=headers)
        if response.status_code == 200:
            num = re.findall('"vuln-matching-records-count">(.*)?</strong>', response.text)[0]
            msg = 'There are {} cves with {} {}...'.format(num, software, banner)
            print(msg)
    except:
        pass
    # fetch all cve no
    start_index = index = 0
    while start_index < int(num):
        url = 'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=' \
              'cpe:/a:{}:{}:{}&startIndex={}'.format(producer, software, banner, start_index)

        msg = 'processing page {}/{}...'.format(index+1, math.ceil(int(num) / 20))
        print(msg)
        index += 1
        start_index = index * 20
        try:
            response = requests.get(url, timeout=60, headers=headers)
            if response.status_code == 200:
                cves = re.findall('"vuln-detail-link-\d+">(.*)?</a>', response.text)
                cve_all.extend(cves)
        except:
            pass
    return url


def fetch_severity(index, total, CVE):
    url = 'https://nvd.nist.gov/vuln/detail/{}'.format(CVE)
    info = '[{} / {}] {}'.format(index, total, url)
    print(info)

    try:
        resp = requests.get(url, timeout=5, headers=headers)
        if resp.status_code == 200:
            content = resp.text
            severity = re.findall('"vuln-cvss3-panel-score">(.*)?</a>', content)
            # print(severity)

            score, cve_level, _ = severity[0].split(' ')
            cve_obj[CVE] = cve_level
            print(score, cve_level)
    except:
        print('v3 not scored, switch to v2...')
        try:
            soup = BeautifulSoup(content, "html.parser")
            score_level = soup.find('a',
                id="p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_Cvss2CalculatorAnchor").get_text()

            score, cve_level = score_level.split(' ')
            cve_obj[CVE] = cve_level
            print(score, cve_level)
        except:
            pass
        pass
    finally:
        pass
    pass


def fetch_vul_info():
    with open(file, 'r') as fr:
        for line in fr:
            global cve_obj
            cve_obj = {}
            producer, software, banner = line.strip().split(',')

            url = fetch_all_cves(producer, software, banner)

            index = 0
            total = len(cve_all)
            for CVE in cve_all:
                index += 1
                fetch_severity(index, total, CVE)

            print(len(cve_obj))
            a = b = c = d = e = 0
            for k, v in cve_obj.items():
                if v == 'CRITICAL':
                    a += 1
                elif v == 'HIGH':
                    b += 1
                elif v == 'MEDIUM':
                    c += 1
                elif v == 'LOW':
                    d += 1
                else:
                    e += 1
            query_str = '{}:{}:{}\n'.format(producer, software, banner)
            vuls_info = '总计:{}\t严重:{}\t高危:{}\t中危:{}\t低危:{}\n'.format(len(cve_obj), a, b, c, d)

            print(query_str)
            print(vuls_info)

            with open('result-v2.txt', 'a+', encoding='utf-8') as fw:
                fw.write(query_str)
                fw.write(url)
                fw.write('\n')
                fw.write(vuls_info)
                for k, v in cve_obj.items():
                    vul_str = '{} - {}\n'.format(k, v)
                    fw.write(vul_str)
                fw.write('\n')


if __name__ == '__main__':

    file = 'list.txt'

    fetch_vul_info()
