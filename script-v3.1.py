#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import re
import math
from bs4 import  BeautifulSoup


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
        print('漏洞描述：', self.cve_description[:10])
        print('漏洞等级：', self.cve_level)
        print('漏洞评分：', self.cve_score)
        print('\n\n')


# cve search url
search_url = 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword='

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

cve_obj_list = []           # cve obj-s fill with detailed information
cve_all = []                # cve no-s fetched from nvd


def fill_with_nvd(cve, cve_obj):
    """
    Fetch detailed information by search cve to fill cve_obj that can be fetch from NVD
    :param cve: cve no
    :param cve_obj: cve object to fill
    :return: None
    """
    cve_obj.cve_no = cve

    nvd_url = 'https://nvd.nist.gov/vuln/detail/'
    url = '{}{}'.format(nvd_url, cve)
    cve_obj.cve_nvd_url = url

    try:
        print(url)
        response = requests.get(url, headers=headers, timeout=60)
        # print(response.status_code)
        if response.status_code == 200:
            # fill description
            content = response.text
            description = re.findall('<p data-testid="vuln-description">(.*).</p>?', content)
            cve_obj.cve_description = description[0]

            severity = re.findall('"vuln-cvss3-panel-score">(.*)?</a>', content)
            # print(severity)
            score, cve_level, _ = severity[0].split(' ')
            cve_obj.cve_score = score
            cve_obj.cve_level = cve_level
            print(score, cve_level)
    except:
        print('v3 not scored, switch to v2...')
        try:
            soup = BeautifulSoup(content, "html.parser")
            score_level = soup.find('a',
                 id="p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_Cvss2CalculatorAnchor").get_text()

            score, cve_level = score_level.split(' ')
            cve_obj.cve_score = score
            cve_obj.cve_level = cve_level
            print(score, cve_level)
        except:
            pass
    finally:
        pass
    pass


def fetch_all_cves(producer, software, banner):
    """
    Query NVD to get specific version of software vulnerabilities
    :return: None
    """
    # contruct query string
    if banner:
        keyword = '{}%3a{}'.format(software, banner)
    else:
        keyword = software
    url = 'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&' \
          'cves=on&cpe_version=cpe%3a%2fa%3a{}%3a{}'.format(producer, keyword)
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
        url = 'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&' \
              'cves=on&cpe_version=cpe%3a%2fa%3a{}%3a{}&' \
              'startIndex={}'.format(producer, keyword, start_index)
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
    print('\n-------- CVEs ---------\n')
    for line in cve_all:
        print(line)
    print()


def fetch_vul_info(producer, software, banner):

    # get all cves
    fetch_all_cves(producer, software, banner)

    i = 0
    for cve in cve_all:
        i += 1
        cve_obj = CveObject()

        # if i == 4:
        #     break
        msg = '[{}/{}] Fetching {} ...'.format(i, cve_all.__len__(), cve)
        print(msg)
        # fill cve object with information from nvd
        fill_with_nvd(cve, cve_obj)
        cve_obj_list.append(cve_obj)
    pass


def save_cve_objs():
    """
    Save cve info to a file
    :return: None
    """
    for obj in cve_obj_list:
        cve_info = '{}|{}|{}|{}|{}|{}\n'.format(obj.cve_no, obj.cve_nvd_url,
                                                       obj.cve_score, obj.cve_level, obj.cve_cna,
                                                       obj.cve_description)
        with open('cve.txt', 'a+') as fw:
            fw.write(cve_info)


def write2html():
    """
    Write cve into to create a html file, this function is terriblely implemented, (^_^)
    :param keyword: software name
    :return: None
    """
    print('write data to html')
    html = ''
    header = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">\
<head>\
    <title>CVEs</title>\
    <meta content="text/html" charset="utf-8"></meta>\
    <link rel="stylesheet" type="text/css" href="list.css">\
</head>\
<body>\
<div id="div_title" align="center">\
    <div id="div_title_inner"><h1>CVEs for {} {} </h1></div>\
</div>\
<div id="div_title_occupy"></div>'

    header = header.format(software, banner)

    body = '<div id="div_main">\
    <div id="div_content"> \
        <div id="div_content_body"><h3>漏洞列表</h3>\
            <div id="uri_list_div">'

    vul_list = ''
    for obj in cve_obj_list:
        vul = '<a href="#{}">{}&nbsp;&nbsp;&nbsp;&nbsp;{}</a><br />'
        vul = vul.format(obj.cve_no, obj.cve_no, obj.cve_level)
        vul_list = '{}{}'.format(vul_list, vul)

    vul_left = '</div>\
        </div>\
    </div>\
    <div id="div_body">'

    body = '{}{}{}'.format(body, vul_list, vul_left)

    table = '<a name="vul-overview"></a><div id="div_get"> \
                <table class="uri_t" id="uri_table" border="1">\
                    <tr align="center">\
                        <td>等级</td>\
                        <td>严重</td>\
                        <td>高危</td>\
                        <td>中危</td>\
                        <td>低危</td>\
                    </tr>\
                    <tr align="center">\
                        <td>个数({})</td>\
                        <td>{}</td>\
                        <td>{}</td>\
                        <td>{}</td>\
                        <td>{}</td>\
                    </tr>\
                </table>\
            </div>'

    a = b = c = d = e = 0
    for cve in cve_obj_list:
        if cve.cve_level == 'CRITICAL':
            a += 1
        elif cve.cve_level == 'HIGH':
            b += 1
        elif cve.cve_level == 'MEDIUM':
            c += 1
        elif cve.cve_level == 'LOW':
            d += 1
        else:
            e += 1

    table = table.format(cve_obj_list.__len__(), a, b, c, d)

    body = '{}{}'.format(body, table)

    for obj in cve_obj_list:
        cve_body = '<a name="{}"></a>\
            <div id="div_get">\
                <table class="uri_t" id="uri_table">\
                    <tr id="cve_no"><th>漏洞编号</th>\
                        <td>{}</td>\
                    </tr>\
                    <tr id="vul_level"><th>威胁评分</th>\
                        <td>{}</td>\
                    </tr>\
                    <tr id="cvss"><th>风险等级</th>\
                        <td>{}</td>\
                    </tr>\
                </table>\
                <p id="description">漏洞描述</p>\
                <div id="example_div"><a id="description">\
                    {}\
                    </a>\
                </div>\
                <p id="references">参考链接</p>\
                <div id="example_div"><a id="references">\
                    {}<br />\
                    </a>\
                </div>\
            </div>'

        cve_body = cve_body.format(obj.cve_no, obj.cve_no, obj.cve_score, obj.cve_level,
                                   obj.cve_description, obj.cve_nvd_url)

        body = '{}{}'.format(body, cve_body)

    footer = '</div>\
</div>\
<script>\
    function AjustContentHeight(){\
        var div_content = document.getElementById("div_content");\
        var div_body = document.getElementById("div_body")\
        var clientHeight = document.documentElement.clientHeight;\
        clientHeight -= 69;\
        div_content.style.height = clientHeight + "px";\
        div_body.style.height = clientHeight + "px";\
    }\
    window.onload=function(){AjustContentHeight();}\
    window.onresize=function(){AjustContentHeight();\
 }\
</script>\
</body>\
</html>'
    html = '{}{}{}'.format(header, body, footer)

    # write to cve html file for showing results
    file = 'cve-{}-{}.html'.format(software, banner)
    with open(file, 'w', encoding='utf-8') as fw:
        fw.write(html)


if __name__ == '__main__':
    file = 'list.txt'
    with open(file, 'r') as fr:
        for line in fr:
            cve_obj_list = []
            cve_all = []
            producer, software, banner = line.strip().split(',')
            print(producer, software, banner)

            fetch_vul_info(producer, software, banner)
            for obj in cve_obj_list:
                obj.show()
            write2html()
            save_cve_objs()
            pass
