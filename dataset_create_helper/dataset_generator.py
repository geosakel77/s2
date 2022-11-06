"""
<Cyber Threat Intelligence Quality Metrics Library and Datasets.>
    Copyright (C) 2022  Georgios Sakellariou

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import os
from hashlib import sha1
from random import randint, shuffle
from time import sleep

import requests
from bs4 import BeautifulSoup

from dbmanager import DBManager


class SourceExtractor:

    def __init__(self, filename):
        self.soup = None
        with open(filename, 'r', encoding='utf-8') as html_doc:
            self.soup = BeautifulSoup(html_doc, 'html.parser')
            html_doc.close()

    def print_html(self):
        print(self.soup.prettify())

    def get_cisa(self):
        data_length = len(self.soup.find_all('span', class_='field-content'))
        entries = {}
        for i in range(data_length):
            code = sha1(self.soup.find_all('span', class_='field-content')[i].getText().encode()).hexdigest()
            href = self.soup.find_all('span', class_='field-content')[i].findNext().get('href')
            title = self.soup.find_all('span', class_='field-content')[i].findNext().getText()
            data = (href, title)
            entries[code.split('\n')[0]] = data
        return entries

    def get_jpcert(self):
        data_length = len(self.soup.find_all('table', class_='table_list')[0].find_all_next('tr'))
        entries = {}
        for i in range(data_length):
            entry = self.soup.find_all('table', class_='table_list')[0].find_all_next('tr')[i]
            code = sha1(entry.getText().encode()).hexdigest()
            href = entry.findNext('td', class_='event_detail').findNext().get('href')
            title = entry.findNext('td', class_='event_detail').findNext().getText()
            texturl = entry.findAllNext('td', class_='c')[1].findNext().get('href')
            data = (href, title, texturl)
            entries[code] = data
        return entries

    def get_aucert(self):
        entries = {}
        dataset = self.soup.find_all('div', class_='field-content')
        for entry in dataset:
            href = entry.findNext('a').get('href')
            title = entry.findNext('a').get('title')
            data = (href, title)
            code = sha1(title.encode()).hexdigest()
            entries[code] = data
        return entries

    def get_bdcert(self):
        entries = {}
        dataset = self.soup.find_all('a', class_='readmore')
        for entry in dataset:
            href = entry.get('href')
            title = href.split('/')[3]
            code = sha1(title.encode()).hexdigest()
            data = (href, title)
            entries[code] = data
        return entries

    def get_aucert_reports(self):
        entries = {}
        dataset = self.soup.find_all('div', class_='field-content')
        for entry in dataset:
            href = entry.findNext('a').get('href')
            title = entry.findNext('a').get('title')
            data = (href, title)
            code = sha1(title.encode()).hexdigest()
            entries[code] = data
        return entries

    def get_cisa_reports(self):
        entries = {}
        dataset = self.soup.find_all('span', class_='field-content document-id')
        for entry in dataset:
            code = sha1(entry.getText().encode()).hexdigest()
            href = entry.findNext('a').get('href')
            title = entry.findNext('a').getText()
            data = (href, title)
            entries[code] = data
        return entries


class SourceManager:

    def __init__(self, alerts_path="../raw_data/html/alerts", reports_path="../raw_data/html/reports"):
        self.alerts_path = alerts_path
        self.reports_path = reports_path
        self.alerts = self._get_alerts_files()
        self.reports = self._get_reports_files()
        self.dbmanager = DBManager()

    def _get_alerts_files(self):
        alert_files = [os.path.join(self.alerts_path, file) for file in os.listdir(self.alerts_path)]
        return alert_files

    def _get_reports_files(self):
        report_files = [os.path.join(self.reports_path, file) for file in os.listdir(self.reports_path)]
        return report_files

    def extract_alerts(self):
        jpcert_alerts = []
        bgd_alerts = []
        au_alerts = []
        cisa_alerts = []
        for alert_file in self.alerts:
            if 'JPCERT' in alert_file:
                jpcert_alerts.append(SourceExtractor(alert_file).get_jpcert())
            elif 'CISA' in alert_file:
                cisa_alerts.append(SourceExtractor(alert_file).get_cisa())
            elif 'BGD' in alert_file:
                bgd_alerts.append(SourceExtractor(alert_file).get_bdcert())
            elif 'gov.au' in alert_file:
                au_alerts.append(SourceExtractor(alert_file).get_aucert())
            else:
                print("Data Cleaner has not specified")
        extracted_alerts = {'JPCERT': jpcert_alerts, 'BGD': bgd_alerts, 'AU': au_alerts, 'CISA': cisa_alerts}
        return extracted_alerts

    def extract_reports(self):
        au_reports = []
        cisa_reports = []
        for report_file in self.reports:
            if 'CISA' in report_file:
                cisa_reports.append(SourceExtractor(report_file).get_cisa_reports())
            elif 'gov.au' in report_file:
                au_reports.append(SourceExtractor(report_file).get_aucert_reports())
            else:
                print("Data Cleaner has not specified")
        extracted_reports = {'AU': au_reports, 'CISA': cisa_reports}
        return extracted_reports

    def insert_alerts(self):
        all_alerts = self.extract_alerts()
        counter = 0
        for key in all_alerts.keys():
            for alert_collection in all_alerts[key]:
                for alert_key in alert_collection.keys():
                    if key is 'JPCERT':
                        self.dbmanager.insert_ctiproduct_alert(alert_key, False, alert_collection[alert_key][0],
                                                               alert_collection[alert_key][1],
                                                               alert_collection[alert_key][2], key)
                    else:
                        self.dbmanager.insert_ctiproduct_alert(alert_key, False, alert_collection[alert_key][0],
                                                               alert_collection[alert_key][1], "nourl", key)
                    counter += 1
                    print(counter)
        print("Total alerts inserted: " + str(counter))

    def insert_reports(self):
        all_reports = self.extract_reports()
        counter = 0
        for key in all_reports.keys():
            for report_collection in all_reports[key]:
                for report_key in report_collection.keys():
                    self.dbmanager.insert_ctiproduct_report(report_key, False, report_collection[report_key][0],
                                                            report_collection[report_key][1], "nourl", key)
                    counter += 1
                    print(counter)
        print("Total reports inserted: " + str(counter))


class CrawlerManager:

    def __init__(self):
        self.dbmanager = DBManager()
        self.headers = [{'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET',
                         'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '3600',
                         'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'},
                        {'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET',
                         'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '3600',
                         'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'},
                        {'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET',
                         'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '3600',
                         'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9'}]

    def write_alert(self, alert, code, source, alerts_path="../raw_data/html_files/alerts", suffix="html"):
        filename = source + "_" + code + "." + suffix
        with open(os.path.join(alerts_path, filename), 'w', encoding='utf-8') as htmlfile:
            htmlfile.write(alert)
            htmlfile.close()

    def write_report(self, report, code, source, reports_path="../raw_data/html_files/reports", suffix="html"):
        filename = source + "_" + code + "." + suffix
        with open(os.path.join(reports_path, filename), 'w', encoding='utf-8') as htmlfile:
            htmlfile.write(report)
            htmlfile.close()

    def get_reports(self):
        reports = self.dbmanager.get_reports()
        shuffle(reports)
        return reports

    def get_alerts(self):
        alerts = self.dbmanager.get_alerts()
        shuffle(alerts)
        return alerts

    def get_content(self, url, headers):
        index = randint(1, 3) - 1
        req = requests.get(url, headers=headers[index])
        content = BeautifulSoup(req.content, 'html.parser').prettify()
        return content

    def _seed_generator(self, source):
        if source == 'JPCERT':
            iv = randint(1, 5)
        elif source == 'BGD':
            iv = randint(2, 6)
        elif source == 'AU':
            iv = randint(3, 7)
        elif source == 'CISA':
            iv = randint(4, 8)
        else:
            iv = 1
        seed = randint(iv, 9)
        return seed

    def hanlde_alerts(self, alerts):
        counter = 0
        for alert in alerts:
            code = alert[0]
            collected = alert[1]
            source = alert[4]
            suffix = "html"
            alerts_path = "../raw_data/html_files/alerts"
            if not collected:
                if alert[3] != 'nourl':
                    if alert[3] is not None:
                        href = alert[3]
                        suffix = "txt"
                        alerts_path = "../datasets/text_files/alerts"
                    else:
                        href = None
                else:
                    href = alert[2]
                if href is not None:
                    try:
                        print(alert)
                        self.write_alert(alert=self.get_content(href, self.headers), code=code, source=source,
                                         alerts_path=alerts_path, suffix=suffix)
                        self.dbmanager.update_alert(code, True)
                        counter += 1
                        print("{}-Successfully crawled alert href : {}".format(counter, href))
                        seed = self._seed_generator(source=source)
                        print(seed)
                        sleep(seed)
                    except Exception as e:
                        print(e)
                else:
                    self.dbmanager.update_alert(code, True)
            else:
                print(alert[0])

    def hanlde_reports(self, reports):
        counter = 0
        for report in reports:
            code = report[0]
            collected = report[1]
            source = report[4]
            suffix = "html"
            reports_path = "../raw_data/html_files/reports"
            if not collected:
                if report[3] != 'nourl':
                    if report[3] is not None:
                        href = report[3]
                        suffix = "txt"
                        reports_path = "../datasets/text_files/reports"
                    else:
                        href = None
                else:
                    href = report[2]
                if href is not None:
                    try:
                        print(report)
                        self.write_report(report=self.get_content(href, self.headers), code=code, source=source,
                                          reports_path=reports_path, suffix=suffix)
                        self.dbmanager.update_report(code, True)
                        counter += 1
                        print("{}-Successfully crawled report href : {}".format(counter, href))
                        seed = self._seed_generator(source=source)
                        print(seed)
                        sleep(seed)
                    except Exception as e:
                        print(e)
                else:
                    self.dbmanager.update_report(code, True)
            else:
                print(report[0])

    def main(self):
        alerts = self.get_alerts()  # [url1,url2]
        reports = self.get_reports()
        self.hanlde_alerts(alerts)
        self.hanlde_reports(reports)


if __name__ == "__main__":
    pass
