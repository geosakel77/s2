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

from bs4 import BeautifulSoup


class DataCleaner:

    def __init__(self, clean_alerts_path="../datasets/text_files/alerts",
                 clean_reports_path="../datasets/text_files/reports", dirty_alerts_path="../raw_data/html_files/alerts",
                 dirty_reports_path="../raw_data/html_files/reports"):
        self.clean_alerts_path = clean_alerts_path
        self.clean_reports_path = clean_reports_path
        self.dirty_alerts_path = dirty_alerts_path
        self.dirty_reports_path = dirty_reports_path

    def get_dirty_alerts_files(self):
        dirty_alerts_files = os.listdir(self.dirty_alerts_path)
        return dirty_alerts_files

    def get_dirty_reports_files(self):
        dirty_reports_files = os.listdir(self.dirty_reports_path)
        return dirty_reports_files

    def get_clean_alerts(self):
        clean_alerts_files = [os.path.join(self.clean_alerts_path, file) for file in os.listdir(self.clean_alerts_path)]
        return clean_alerts_files

    def get_clean_reports(self):
        clean_reports_files = [os.path.join(self.clean_reports_path, file) for file in os.listdir(self.clean_reports_path)]
        return clean_reports_files

    def clean_alerts(self):
        for alert in self.get_dirty_alerts_files():
            htmlfilename = os.path.join(self.dirty_alerts_path, alert)
            alert_to_text = TextExtractor(htmlfilename).get_text()
            self.write_alert(alert_to_text, alert.split('.')[0])
            print("Alert : {} cleaned".format(alert))

    def clean_reports(self):
        for report in self.get_dirty_reports_files():
            htmlfilename = os.path.join(self.dirty_reports_path, report)
            report_to_text = TextExtractor(htmlfilename).get_text()
            self.write_report(report_to_text,report.split('.')[0])
            print("Report : {} cleaned".format(report))

    def write_alert(self, alert, filenameprefix, suffix="txt"):
        filename = filenameprefix + "." + suffix
        with open(os.path.join(self.clean_alerts_path, filename), 'w', encoding='utf-8') as txtfile:
            txtfile.write(alert)
            txtfile.close()

    def write_report(self, report, filenameprefix, suffix="txt"):
        filename = filenameprefix + "." + suffix
        with open(os.path.join(self.clean_reports_path, filename), 'w', encoding='utf-8') as txtfile:
            txtfile.write(report)
            txtfile.close()


class TextExtractor:

    def __init__(self, filename):
        self.soup = None
        with open(filename, 'r', encoding='utf-8') as html_doc:
            self.soup = BeautifulSoup(html_doc, 'html.parser')
            html_doc.close()

    def print_html(self):
        print(self.soup.prettify())

    def get_text(self):
        for data in self.soup(['style', 'script']):
            data.decompose()
        return ' '.join(self.soup.stripped_strings)


if __name__ == "__main__":
    cleaner = DataCleaner()

    cleaner.clean_alerts()
    cleaner.clean_reports()
    print(len(cleaner.get_clean_alerts()))
    print(len(cleaner.get_clean_reports()))
