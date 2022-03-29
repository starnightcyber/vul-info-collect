# vul-info-collect

漏洞信息统计，用于获取特定软件版本漏洞的简要统计信息:CVE，漏洞总数、严重、高危、中危、低危漏洞个数，以及简单的文本和网页展示效果。

## 更新日志

`2022.3.29` `add` `search_vuls.py`

`2020.1.18` `modify` `script-v2.py & script-v3.py`	
`修改脚本以适应NVD界面变化 & cvss v3未评分异常。`
## search_vuls.py

搜索特定软件，获取其所有漏洞，以列表的形式给出，便于手工按照漏洞优先级逐一排查。

```
python3 search_vuls.py
please input which sofware you want to search vuls ... 
=> kong
[*] checking https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=kong ...
[+] => ['CVE-2021-32753', 'CVE-2021-27306', 'CVE-2020-35189', 'CVE-2020-11710', 'CVE-2018-0269', 'CVE-2014-7057']
[*] task qsize => 6
[2] fetch ... https://nvd.nist.gov/vuln/detail/CVE-2021-27306
[1] fetch ... https://nvd.nist.gov/vuln/detail/CVE-2021-32753
[3] fetch ... https://nvd.nist.gov/vuln/detail/CVE-2020-35189
[4] fetch ... https://nvd.nist.gov/vuln/detail/CVE-2020-11710
[5] fetch ... https://nvd.nist.gov/vuln/detail/CVE-2018-0269
[6] fetch ... https://nvd.nist.gov/vuln/detail/CVE-2014-7057
v3 not scored, switch to v2...
+-----+----------------+-------+----------+-------------------------------------------------+
| No. |      CVE       | Score |  Level   |                       URL                       |
+-----+----------------+-------+----------+-------------------------------------------------+
|  1  | CVE-2018-0269  |  4.3  |  MEDIUM  |  https://nvd.nist.gov/vuln/detail/CVE-2018-0269 |
|  2  | CVE-2020-35189 |  9.8  | CRITICAL | https://nvd.nist.gov/vuln/detail/CVE-2020-35189 |
|  3  | CVE-2021-32753 |  6.5  |  MEDIUM  | https://nvd.nist.gov/vuln/detail/CVE-2021-32753 |
|  4  | CVE-2021-27306 |  7.5  |   HIGH   | https://nvd.nist.gov/vuln/detail/CVE-2021-27306 |
|  5  | CVE-2020-11710 |  9.8  | CRITICAL | https://nvd.nist.gov/vuln/detail/CVE-2020-11710 |
|  6  | CVE-2014-7057  |  5.4  |  MEDIUM  |  https://nvd.nist.gov/vuln/detail/CVE-2014-7057 |
+-----+----------------+-------+----------+-------------------------------------------------+
It costs 9 seconds to run the task
```
## Sample - v3

update:2020.1.3

获取某个软件版本的漏洞总览信息，包括：漏洞个数，严重、高危、中危、低危漏洞个数，漏洞描述等必要信息，及CVE的漏洞等级情况，并以html的形式展现。

A script to get vulnerabilities of specific software version, which contains vul number, vul level, vul description, and CVE no vul level, and present with html.

![image](https://raw.githubusercontent.com/starnightcyber/vul-info-collect/master/pic.png)

## Sample - v2

update:2020.1.3

获取某个软件版本的漏洞总览信息，包括：漏洞个数，严重、高危、中危、低危漏洞个数，及CVE的漏洞等级情况。

A script to get vulnerabilities of specific software version, which contains vul number, vul level and CVE no vul level.

```
PS E:\PycharmProjects\vul-info-collect> python3 .\script-v2.py
apache:http_server:2.4.38
https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:apache:http_server:2.4.38&startIndex=20
总计:38	严重:0	高危:13	中危:22	低危:3
CVE-2019-10081 - 高
CVE-2019-0197 - 中
CVE-2019-0196 - 中
CVE-2019-0220 - 中
...
CVE-1999-1412 - 高
CVE-1999-0678 - 中
CVE-1999-0236 - 高
CVE-1999-0070 - 中

apache:tomcat:7.0.92
https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:apache:tomcat:7.0.92&startIndex=0
总计:7	严重:0	高危:3	中危:2	低危:2
CVE-2019-0221 - 中
CVE-2019-0232 - 高
CVE-2016-5425 - 高
CVE-2011-1571 - 高
CVE-2011-1570 - 低
CVE-2011-1503 - 低
CVE-2011-1502 - 中
```

## Sample - v1

update: outdated

link: https://github.com/starnightcyber/scripts/tree/master/vul-info-collect
