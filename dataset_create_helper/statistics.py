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
import os
import re

import nltk
from nltk.corpus import stopwords


class Statistics:

    def __init__(self, clean_alerts_path="../datasets/text_files/alerts",
                 clean_reports_path="../datasets/text_files/reports", dirty_alerts_path="../raw_data/html_files/alerts",
                 dirty_reports_path="../raw_data/html_files/reports", otx_path="../datasets/stixv2/otx",
                 cpes_path="../datasets/cpes.json", delta_path="../datasets/delta.json", sigma_path="../datasets/sigma_stixv2.json"):
        self.clean_alerts_path = clean_alerts_path
        self.clean_reports_path = clean_reports_path
        self.dirty_alerts_path = dirty_alerts_path
        self.dirty_reports_path = dirty_reports_path
        self.otx_path = otx_path
        self.cpes_path = cpes_path
        self.stop_words = set(stopwords.words('english'))
        self.delta_path = delta_path
        self.sigma_path =sigma_path

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
        count_bundles = 0
        objects_types = []
        objects_per_type = {}
        observable_types = []
        objects_per_observable_type = {}
        for stixv2file in self._get_otx_files_paths():
            count_bundles += 1
            with open(stixv2file, 'r') as jsonfile:
                stixv2 = json.load(jsonfile)
                jsonfile.close()
            for object in stixv2['objects']:
                object_type = object["id"].split("--")[0]
                if object_type not in objects_types:
                    objects_types.append(object_type)
                    objects_per_type[object_type] = 0
                if object_type == 'indicator':
                    object_observable = object['pattern']
                    if 'rule' not in object_observable:
                        a = object_observable.replace("[", "")
                        b = a.replace("]", "")
                        observable_type = b.split("=")[0].strip()
                        if observable_type not in observable_types:
                            observable_types.append(observable_type)
                            objects_per_observable_type[observable_type] = 0
                        objects_per_observable_type[observable_type] += 1
                objects_per_type[object_type] += 1
        temp_text = ""
        temp_text_observable = "Observables:\n"
        for observable_type in observable_types:
            temp_text_observable = temp_text_observable + "{} objects number: {}\n".format(observable_type,
                                                                                           objects_per_observable_type[
                                                                                               observable_type])

        for object_type in objects_types:
            temp_text = temp_text + "{} objects number: {}\n".format(object_type, objects_per_type[object_type])
        text_formated = "Stixv2 files number: {}\n" \
                        "Bundle objects number: {}\n" \
                        "{}" \
                        "{}".format(len(self._get_otx_files_paths()), count_bundles, temp_text, temp_text_observable)
        return text_formated

    def _get_cpe_statistics(self):
        statistics = {}
        with open(self.cpes_path, 'r') as cpesfile:
            cpes = json.load(cpesfile)
            cpesfile.close()
        statistics['cpes_number'] = len(cpes)
        application_cpes_num = 0
        os_cpes_num = 0
        hardware_cpes_num = 0
        for cpe in cpes:
            if cpe['part'] == "applications":
                application_cpes_num += 1
            elif cpe['part'] == "operating systems":
                os_cpes_num += 1
            elif cpe['part'] == "hardware devices":
                hardware_cpes_num += 1
        statistics['hardware'] = hardware_cpes_num
        statistics['os'] = os_cpes_num
        statistics['app'] = application_cpes_num
        return statistics

    def _get_delta_statistics(self):
        statistics = {}
        with open(self.delta_path, 'r') as deltafile:
            delta = json.load(deltafile)
            deltafile.close()
        statistics['delta'] = len(delta.keys())
        return statistics

    def _get_sigma_statistics(self):
        statistics = {}
        with open(self.sigma_path, 'r') as sigmafile:
            sigma = json.load(sigmafile)
            sigmafile.close()
        statistics['sdos'] = len(sigma['sdos'].keys())
        statistics['observables'] = len(sigma['observables'].keys())
        statistics['common'] = len(sigma['common'].keys())
        statistics['sros'] = len(sigma['sros'].keys())
        return statistics

    def print_statistics(self):
        alerts_number = len(statistics._get_clean_alerts())
        reports_number = len(statistics._get_clean_reports())
        alerts_statistics = self._get_alerts_statistics()
        reports_statistics = self._get_reports_statistics()
        stixv2_statistics = self._get_stixv2_statistics()
        delta_statistics = self._get_delta_statistics()
        sigma_statistics = self._get_sigma_statistics()
        cpes_statistics = self._get_cpe_statistics()
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
                 "{}" \
                 "############################################\n" \
                 "CPEs number: {}\n" \
                 "Application CPEs  number: {}\n" \
                 "Operating System CPEs number: {}\n" \
                 "Hardware CPEs number: {}\n" \
                 "############################################\n" \
                 "Delta Industry domains number: {}\n" \
                 "############################################\n" \
                 "Stix V2.1 schema sdos objects: {} \n" \
                 "Stix V2.1 schema observables objects: {} \n" \
                 "Stix V2.1 schema common objects: {}\n" \
                 "Stix V2.1 schema sros objects: {}\n" \
                 "############################################\n".format(alerts_number, sources_alerts.count('AU'),
                                                                         sources_alerts.count('BGD'),
                                                                         sources_alerts.count('CISA'),
                                                                         sources_alerts.count('JPCERT'),
                                                                         avg_alert_words, reports_number,
                                                                         sources_reports.count('AU'),
                                                                         sources_reports.count('CISA'),
                                                                         avg_report_words,
                                                                         stixv2_statistics,
                                                                         cpes_statistics['cpes_number'],
                                                                         cpes_statistics['app'], cpes_statistics['os'],
                                                                         cpes_statistics['hardware'],
                                                                         delta_statistics['delta'],sigma_statistics['sdos'],
                                                                         sigma_statistics['observables'],sigma_statistics['common'],
                                                                         sigma_statistics['sros'])
        print(report)


if __name__ == "__main__":
    statistics = Statistics()
    statistics.print_statistics()
