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

import json
import nltk
import os
import re

from nltk.corpus import stopwords


class Statistics:

    def __init__(self, clean_alerts_path="../datasets/text_files/alerts",
                 clean_reports_path="../datasets/text_files/reports", dirty_alerts_path="../raw_data/html_files/alerts",
                 dirty_reports_path="../raw_data/html_files/reports", otx_path="../datasets/stixv2/otx"):
        self.clean_alerts_path = clean_alerts_path
        self.clean_reports_path = clean_reports_path
        self.dirty_alerts_path = dirty_alerts_path
        self.dirty_reports_path = dirty_reports_path
        self.otx_path = otx_path
        self.stop_words = set(stopwords.words('english'))

    def _get_otx_files(self):
        otx_files = os.listdir(self.otx_path)
        return otx_files

    def _get_clean_alerts(self):
        clean_alerts_files = os.listdir(self.clean_alerts_path)
        return clean_alerts_files

    def _get_clean_reports(self):
        clean_reports_files = os.listdir(self.clean_reports_path)
        return clean_reports_files

    def _get_otx_files_paths(self):
        otx_files = [os.path.join(self.otx_path, file) for file in os.listdir(self.otx_path)]
        return otx_files

    def _get_clean_alerts_paths(self):
        clean_alerts_files = [os.path.join(self.clean_alerts_path, file) for file in os.listdir(self.clean_alerts_path)]
        return clean_alerts_files

    def _get_clean_reports_paths(self):
        clean_reports_files = [os.path.join(self.clean_reports_path, file) for file in
                               os.listdir(self.clean_reports_path)]
        return clean_reports_files

    def _get_alerts_statistics(self):
        statistics = {}
        sources = []
        for alert in self._get_clean_alerts():
            sources.append(alert.split('_')[0])
        statistics['sources'] = sources
        count_words = 0
        for alert in self._get_clean_alerts_paths():
            with open(alert, 'r', encoding='utf-8') as textfile:
                document = textfile.read()
                textfile.close()
            tokens = nltk.word_tokenize(re.sub(r"[^a-zA-Z0-9 ]", "", document))
            filtered_tokens = [w for w in tokens if not w.lower() in self.stop_words]
            count_words += len(filtered_tokens)
        statistics['words_avg'] = count_words / len(self._get_clean_reports())
        return statistics

    def _get_reports_statistics(self):
        statistics = {}
        sources = []
        for report in self._get_clean_reports():
            sources.append(report.split('_')[0])
        statistics['sources'] = sources

        count_words = 0
        for report in self._get_clean_reports_paths():
            with open(report, 'r', encoding='utf-8') as textfile:
                document = textfile.read()
                textfile.close()
            tokens = nltk.word_tokenize(re.sub(r"[^a-zA-Z0-9 ]", "", document))
            filtered_tokens = [w for w in tokens if not w.lower() in self.stop_words]
            count_words += len(filtered_tokens)
        statistics['words_avg'] = count_words / len(self._get_clean_reports())

        return statistics

    def _get_stixv2_statistics(self):
        statistics = {}
        count_indicators = 0
        for stixv2file in self._get_otx_files_paths():
            with open(stixv2file, 'r') as jsonfile:
                stixv2 = json.load(jsonfile)
                jsonfile.close()
            count_indicators += len(stixv2['objects'][0]['object_refs'])
        statistics['indicators_number'] = count_indicators
        return statistics

    def _get_cpe_statistics(self):
        pass

    def _get_delta_statistics(self):
        pass

    def _get_sigma_statistics(self):
        pass

    def print_statistics(self):
        alerts_number = len(statistics._get_clean_alerts())
        reports_number = len(statistics._get_clean_reports())
        stixv2_number = len(statistics._get_otx_files())
        alerts_statistics = self._get_alerts_statistics()
        reports_statistics = self._get_reports_statistics()
        stixv2_statistics = self._get_stixv2_statistics()
        sources_alerts = alerts_statistics['sources']
        sources_reports = reports_statistics['sources']
        avg_alert_words = alerts_statistics['words_avg']
        avg_report_words = reports_statistics['words_avg']

        report = "CTI Dataset Statistics Report\n" \
                 "-------------------------------------------\n" \
                 "Alert files number: {}\n" \
                 "############################################\n" \
                 "Alerts of AU: {}\n" \
                 "Alerts of BGD: {}\n" \
                 "Alerts of CISA: {}\n" \
                 "Alerts of JPCERT: {}\n" \
                 "Average words per alert file : {}\n" \
                 "############################################\n" \
                 "Report files number: {}\n" \
                 "############################################\n" \
                 "Reports of AU: {}\n" \
                 "Reports of CISA: {}\n" \
                 "Average words per report file : {}\n" \
                 "############################################\n" \
                 "Stixv2 files number: {}\n" \
                 "Bundle objects number: {}\n" \
                 "Indicators objects number: {}\n" \
                 "############################################\n".format(alerts_number, sources_alerts.count('AU'),
                                                                         sources_alerts.count('BGD'),
                                                                         sources_alerts.count('CISA'),
                                                                         sources_alerts.count('JPCERT'),
                                                                         avg_alert_words, reports_number,
                                                                         sources_reports.count('AU'),
                                                                         sources_reports.count('CISA'),
                                                                         avg_report_words,
                                                                         stixv2_number, stixv2_number,
                                                                         stixv2_statistics['indicators_number'])
        print(report)


if __name__ == "__main__":
    statistics = Statistics()
    statistics.print_statistics()
