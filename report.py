# -*- coding:utf-8 -*-
# @Time : 2020/3/8 20:08
# @Author : naihai
import json

import requests
from bs4 import BeautifulSoup
import os

headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                            (KHTML, like Gecko) Chrome/69.0.3497.81 Safari/537.36',
}


class Report(object):
    def __init__(self, user_name_, user_pass_, server_id_):
        self.user_name = user_name_
        self.user_pass = user_pass_

        self.session = requests.session()
        self.session.headers.update(headers)

        self.server_id = server_id_
        self.resource_id = ""
        self.process_id = ""
        self.user_id = ""
        self.form_id = ""
        self.privilege_id = ""

        self.base_url = "https://thos.tsinghua.edu.cn"

        self.report_url = "https://thos.tsinghua.edu.cn/fp/view?m=fp#from=hall&" \
                          "serveID={0}&" \
                          "act=fp/serveapply".format(self.server_id)

        self.common_referer = "https://thos.tsinghua.edu.cn/fp/view?m=fp"

        self.headers = {
            'authority': 'thos.tsinghua.edu.cn',
            'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="98", "Google Chrome";v="98"',
            'accept': 'application/json, text/javascript, */*; q=0.01',
            'content-type': 'application/json;charset=UTF-8',
            'x-requested-with': 'XMLHttpRequest',
            'sec-ch-ua-mobile': '?0',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36',
            'sec-ch-ua-platform': '"macOS"',
            'origin': 'https://thos.tsinghua.edu.cn',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'referer': 'https://thos.tsinghua.edu.cn/fp/view?m=fp',
            'accept-language': 'zh-CN,zh;q=0.9'
        }
        
        self.form_data = None

    def run(self):
        self.__login()
        self.__get_server_info()
        self.__get_data()
        self.__submit_report()

    def __login(self):
        """登录 获取cookie"""

        res1 = self.session.get(self.base_url, headers=headers)  # 重定向到登录页面

        login_url_ = "https://id.tsinghua.edu.cn/do/off/ui/auth/login/check"
        headers_ = headers
        headers_["Referer"] = self.common_referer
        data_ = {
            "i_user": self.user_name,
            "i_pass": self.user_pass,
        }

        res2 = self.session.post(login_url_, data=data_, headers=headers_)
        # 登录成功 会重定向到 在线服务页面
        soup2 = BeautifulSoup(res2.text, 'html.parser')
        redirect_url = soup2.find("a")["href"]
        self.session.get(redirect_url)

        # 验证是否登录成功
        res3 = self.session.get(url=self.report_url, headers=headers)
        soup3 = BeautifulSoup(res3.text, 'html.parser')
        if soup3.find('form', attrs={'class': 'form-signin'}) is not None:
            print("登录失败")
            raise RuntimeError("Login Failed")
        else:
            self.session.headers.update(res3.headers)
            self.cookies = self.session.cookies
            print("登录成功")

    def __get_server_info(self):
        """
        获取服务器提供的一些参数
        resource_id
        formid
        procID
        privilegeId
        """
        url_ = "https://thos.tsinghua.edu.cn/fp/fp/serveapply/getServeApply"

        

        cookies_ = self.session.cookies

        data = {"serveID": self.server_id, "from": "hall"}
        try:
            response = requests.get(url=url_, headers=self.headers,
                                    cookies=self.cookies, data=json.dumps(data), timeout=60)
            result = response.json()

            self.resource_id = result["resource_id"]
            self.user_id = result["user_id"]
            self.form_id = result["formID"]
            self.process_id = result["procID"]
            self.privilege_id = result["privilegeId"]
            print("获取服务器参数成功")
        except Exception as e:
            print("获取服务器参数失败", e)
            raise RuntimeError("Get server info failed")

    def __get_data(self):
        """获取表单信息"""
        url_ = "https://thos.tsinghua.edu.cn/fp/formParser?" \
               "status=select&" \
               "formid={0}&" \
               "service_id={1}&" \
               "process={2}&" \
               "privilegeId={3}".format(self.form_id,
                                        self.server_id,
                                        self.process_id,
                                        self.privilege_id)

        response = requests.get(url=url_, headers=self.headers,
                                cookies=self.cookies, timeout=60)
        soup = BeautifulSoup(response.text, 'html.parser')
        form_data_str = soup.find("script", attrs={"id": "dcstr"}).contents[0]

        self.form_data = eval(form_data_str, type('js', (dict,), dict(__getitem__=lambda k, n: n))())

    def __submit_report(self):
        url_ = "https://thos.tsinghua.edu.cn/fp/formParser?" \
               "status=update&" \
               "formid={0}&" \
               "workflowAction=startProcess&" \
               "workitemid=&" \
               "process={1}".format(self.form_id,
                                    self.process_id)

        referer_url_ = "https://thos.tsinghua.edu.cn/fp/formParser?" \
                       "status=select&" \
                       "formid={0}&" \
                       "service_id={1}&" \
                       "process={2}&" \
                       "privilegeId={3}".format(self.form_id,
                                                self.server_id,
                                                self.process_id,
                                                self.privilege_id)

        response = requests.post(url=url_, headers=self.headers,
                                cookies=self.cookies, data=json.dumps(self.form_data))
        if response.status_code == requests.codes.OK:
            print("提交健康日报成功")
        else:
            print("提交健康日报失败")


def load_info():
    config = {}
    with open("conf.ini", "r") as rf:
        for line in rf.readlines():
            config[line.split("=")[0]] = line.split("=")[1].strip()
    return config


if __name__ == '__main__':
    # 首先检查环境变量中是否存在 USER_NAME USER_PASS
    # 该功能用于Github Action部署
    if os.getenv("USER_NAME") and os.getenv("USER_PASS"):
        print("User info found in env")
        user_name = os.getenv("USER_NAME")
        user_pass = os.getenv("USER_PASS")
        server_id = os.getenv("SERVER_ID")
    else:
        info = load_info()
        user_name = info["USER_NAME"]
        user_pass = info["USER_PASS"]
        server_id = info["SERVER_ID"]
    Report(user_name, user_pass, server_id).run()
