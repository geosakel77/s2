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
import itertools
import json
import time
from statistics import mean
from re_experiment_preparation import write_json
from nltk.probability import FreqDist
from metrics.relevance import re_metric


def load_data():
    all_delta_p1 = _load('all_organizations_delta_p1.json')
    all_delta_p2 = _load('all_organizations_delta_p2.json')
    all_giota = _load('all_organizations_giota_transformed.json')
    all_delta = _load('all_organizations_delta_transformed.json')
    return all_delta_p1, all_giota, all_delta_p2, all_delta


def _load(path):
    with open(path, 'r', encoding='utf-8') as jsonfile:
        data = json.load(jsonfile)
        jsonfile.close()
    return data


def _find_delta_p2(item_id, all_delta_p2):
    result = None
    for delta_p2 in all_delta_p2:
        if delta_p2[1] == item_id:
            result = delta_p2[0]
    return result


def _experiment_1_per_organization(all_delta_p1, all_giota, all_delta_p2, all_delta):
    organization_results = {}
    for item in all_delta_p1:
        delta_p1 = []
        delta_giota = []
        item_id = item[1]
        item_data = item[0]
        for item_key in item_data.keys():
            delta_p1.append(item_data[item_key])
            delta_giota.append(all_giota[item_key])
        delta_p2 = _find_delta_p2(item_id, all_delta_p2)
        organization_results[item_id] = re_metric(delta_p1=delta_p1, delta_i=delta_giota, delta_p2=delta_p2,
                                                  delta_d=all_delta)
    return organization_results


def _avg_per_organization(results):
    value = mean(list(results.values()))
    return value


def experiment_1(all_delta_p1, all_giota, all_delta_p2, all_delta):
    results_all = {}
    organizations = all_delta_p2.keys()
    for organization in organizations:
        results = _experiment_1_per_organization(all_delta_p1[organization], all_giota[organization],
                                                 all_delta_p2[organization], all_delta[organization])
        results_all[organization] = _avg_per_organization(results)
    return results_all


def _experiment_2_per_organization(all_delta_p1, all_giota, all_delta_p2, all_delta):
    organization_results = {}
    for item in all_delta_p1:
        delta_p1 = []
        delta_giota = []
        item_id = item[1]
        item_data = item[0]
        for item_key in item_data.keys():
            delta_p1.append(item_data[item_key])
            delta_giota.append(all_giota[item_key])
        delta_p2 = _find_delta_p2(item_id, all_delta_p2)
        organization_results[item_id] = re_metric(delta_p1=delta_p1, delta_i=delta_giota, delta_p2=delta_p2,
                                                  delta_d=all_delta)
    return organization_results


def _intesection_results(results):
    values = []
    for organization in results.keys():
        values.append(list(results[organization].keys()))
    flatten_values = list(itertools.chain(*values))
    frequency_matrix = FreqDist(flatten_values)
    data = dict(frequency_matrix.items())
    common_items = []
    for item in data.keys():
        if data[item] == 10:
            common_items.append(item)
    cleaned_results = {}
    for organization in results.keys():
        cleaned_organization_results = {}
        for document in common_items:
            cleaned_organization_results[document] = results[organization][document]
        cleaned_results[organization] = cleaned_organization_results
    print(cleaned_results)
    return cleaned_results


def experiment_2(all_delta_p1, all_giota, all_delta_p2, all_delta):
    results_all = {}
    organizations = all_delta_p2.keys()
    for organization in organizations:
        results = _experiment_2_per_organization(all_delta_p1[organization], all_giota[organization],
                                                 all_delta_p2[organization], all_delta[organization])
        results_all[organization] = results
    return _intesection_results(results_all)


def _experiment_3_organization_documents_creation(all_delta_p1, all_delta_p2, org_id):
    all_delta_p1_extended = []
    all_delta_p2_extended = []
    artificial_id = "artificial_item_{}".format(org_id)
    artificial_p1 = {}
    artificial_p2_temp = []
    for i in range(0, 10 * org_id):
        artificial_p1.update(all_delta_p1[i][0])
        artificial_p2_temp.append(all_delta_p2[i][0])
    artificial_p2 = list(itertools.chain(*artificial_p2_temp))
    print("Artificial Doc p1 of Org:C{} with length:{} created".format(org_id, len(list(artificial_p1.keys()))))
    print("Artificial Doc p2 of Org:C{} with length:{} created".format(org_id, len(artificial_p2)))
    all_delta_p1_extended.append([artificial_p1, artificial_id])
    all_delta_p2_extended.append([artificial_p2, artificial_id])
    return all_delta_p1_extended, all_delta_p2_extended


def _experiment_3_per_organization(all_delta_p1, all_giota, all_delta_p2, all_delta, org_id):
    organization_results = {}
    all_delta_p1_extended, all_delta_p2_extended = _experiment_3_organization_documents_creation(all_delta_p1,
                                                                                                 all_delta_p2, org_id)
    for item in all_delta_p1_extended:
        delta_p1 = []
        delta_giota = []
        item_id = item[1]
        item_data = item[0]
        for item_key in item_data.keys():
            delta_p1.append(item_data[item_key])
            delta_giota.append(all_giota[item_key])
        delta_p2 = _find_delta_p2(item_id, all_delta_p2_extended)
        start_time = time.time()
        start_time_cpu = time.process_time()
        re_value = re_metric(delta_p1=delta_p1, delta_i=delta_giota, delta_p2=delta_p2,
                             delta_d=all_delta * org_id * 10)
        end_time_cpu = time.process_time()
        end_time = time.time()
        organization_results[item_id] = {'value': re_value, 'time': end_time - start_time,
                                         'cpu_time': end_time_cpu - start_time_cpu}
    return organization_results


def experiment_3(all_delta_p1, all_giota, all_delta_p2, all_delta):
    results_all = {}
    for organization in all_delta_p2.keys():
        results = _experiment_3_per_organization(all_delta_p1[organization], all_giota[organization],
                                                 all_delta_p2[organization], all_delta[organization],
                                                 int(organization.replace("C", "")))
        results_all[organization] = results
    return results_all


def re_main():
    all_delta_p1, all_giota, all_delta_p2, all_delta = load_data()
    #data_1 = experiment_1(all_delta_p1, all_giota, all_delta_p2, all_delta)
    #print(data_1)
    #write_json(data1=data_1, filepath='experiment_1_results.json')
    data_2 = experiment_2(all_delta_p1, all_giota, all_delta_p2, all_delta)
    print(data_2)
    #write_json(data1=data_2, filepath='experiment_2_results.json')
    #data_3 = experiment_3(all_delta_p1, all_giota, all_delta_p2, all_delta)
    #print(data_3)
    #write_json(data1=data_3, filepath='experiment_3_results.json')


if __name__ == "__main__":
    re_main()
