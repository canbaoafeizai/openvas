#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import requests
from requests.cookies import RequestsCookieJar
import xml_parse
import time
import os
import parse_csv

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
os_path = os.path.dirname(__file__)
csv_path = os.path.join(os_path,"report","csv")
json_path = os.path.join(os_path , "report","json")


class OpenVAS_API(object):
    def __init__(self, task_name):
        self.openvasurl = "10.122.3.163"
        self.username = "admin"
        self.password = "admin"
        self.base = 'https://{url}'.format(url=self.openvasurl)
        self.gmpurl = self.base + "/gmp"
        self.task_name = task_name
        self.headers = {
            'Origin': self.base,
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.8',
            'User-Agent': 'T1ger for OpenVAS',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Cache-Control': 'max-age=0',
            'Referer': self.base,
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'keep-alive',
        }
        self.cookie_jar = RequestsCookieJar()
        self.proxies = {'http': "http://127.0.0.1:8090",
                        'https': "https://127.0.0.1:8090"}
        date = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
        self.csv_name = self.task_name + "-" + date
        self.report_path = os.path.join(csv_path, self.csv_name + ".csv")
        self.login()
        self.get_report_id()
        self.get_report_csv()

    def login(self):
        data = [
            ('cmd', 'login'),
            ('login', self.username),
            ('password', self.password),
        ]
        #res = requests.post(self.base, data=data, proxies=self.proxies, cookies=self.cookie_jar, headers=self.headers,verify=False)
        res = requests.post(self.base, data=data, cookies=self.cookie_jar, headers=self.headers, verify=False)
        if res.status_code == 200:
            self.cookie_jar = res.cookies
            parse = xml_parse.parse(res.content.decode('utf-8'))
            self.token = parse.get_item_text("token")
            print("login success,token={}".format(self.token))
        else:
            raise Exception('[FAIL] Could not login to OpenVAS')

    def get_report_id(self):
        data = [
            ('token', self.token),
            ('cmd', 'get_tasks'),
            ('usage_type', 'scan'),
            ('filter', "~" + self.task_name + " apply_overrides=0 min_qod=70 sort=name first=1 rows=10")
        ]
        res = requests.get(self.gmpurl, cookies=self.cookie_jar, params=data, headers=self.headers, verify=False)
        #res = requests.get(self.gmpurl, cookies=self.cookie_jar, proxies=self.proxies, params=data,headers=self.headers, verify=False)
        if res.status_code == 200:
            parse = xml_parse.parse(res.content.decode('utf-8'))
            report_id_dict = parse.get_item_attr(".//report")
            self.report_id = report_id_dict['id']
            print("get_report_id_success,id={}".format(self.report_id))
        else:
            print(res.text)
            raise Exception('[FAIL] Could not parse tasksname')

    def get_csv_format_id(self):
        pass

    def get_report_csv(self):
        data = [
            ('token', self.token),
            ('cmd', 'get_report'),
            ('details', '1'),
            ('report_id', self.report_id),
            ('report_format_id', 'c1645568-627a-11e3-a660-406186ea4fc5'),
            ('filter', 'apply_overrides=0 levels=hml rows=-1 min_qod=70 first=1 sort-reverse=severity notes=1 '
                       'overrides=1')
        ]
        res = requests.get(self.gmpurl, cookies=self.cookie_jar, params=data, headers=self.headers, verify=False)
        #res = requests.get(self.gmpurl, cookies=self.cookie_jar, proxies=self.proxies, params=data,headers=self.headers, verify=False)
        # print(res.text)
        if res.status_code == 200:
            f = open(self.report_path, 'w', encoding='utf-8', newline='')
            f.write(res.text)
            f.close()
            print("csv download success,name={}".format(self.report_path))
        else:
            print(res.text)
            raise Exception('[FAIL] Could not parse tasksname')


if __name__ == '__main__':
    task_name = sys.argv[1]
    #task_name = input("Input full report name,run as python3 openvas.py welink-2015-1")
    # task_name = "127.0.0.1"
    csv_report = OpenVAS_API(task_name)
    json_report = parse_csv.parse(csv_report.csv_name)
