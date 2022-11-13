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
import time
from math import ceil
from statistics import mean

from metrics.weighted_completeness import wc_metric, c_metric
from wc_experiment_preparation import write_json


def load_data():
    all_w = _load('all_organizations_w.json')
    sigma = _load('../../datasets/sigma_stixv2.json')
    all_ps = _load('all_organizations_ps_counted.json')
    return all_w, sigma, all_ps


def _load(path):
    with open(path, 'r', encoding='utf-8') as jsonfile:
        data = json.load(jsonfile)
        jsonfile.close()
    return data


def _transform_sigma(sigma):
    transformed_sigma = {}
    for category in sigma.keys():
        for object_type_key in sigma[category].keys():
            transformed_sigma[object_type_key] = sigma[category][object_type_key][1]
    return transformed_sigma


def _experiment_1_per_organization(ps, sigma, weights):
    organization_results = {}
    for object_type in ps.keys():
        signature = None
        if object_type == 'bundles':
            signature = 'bundle'
        elif object_type == 'identities':
            signature = 'identity'
        elif object_type == 'indicators':
            signature = 'indicator'
        elif object_type == 'reports':
            signature = 'report'
        elif object_type == 'threat_actors':
            signature = 'threat-actor'
        elif object_type == 'vulnerabilities':
            signature = 'vulnerability'
        elif object_type == "url":
            signature = "url"
        elif object_type == "email-message":
            signature = "email-message"
        elif object_type == "ipv4-addr":
            signature = "ipv4-addr"
        elif object_type == 'domain-name':
            signature = 'domain-name'
        elif object_type == 'file':
            signature = 'file'
        weight_o = weights[signature]
        sigma_o = sigma[signature]
        object_type_results = []
        objects = ps[object_type]
        for object_t in objects:
            wc_value = wc_metric([weight_o], [object_t[1]], [sigma_o])
            object_type_results.append((object_t[0], wc_value))
        organization_results[signature] = object_type_results
    avg_per_object_type = {}
    for key1 in organization_results.keys():
        values_list = []
        for item in organization_results[key1]:
            values_list.append(item[1])
        avg_per_object_type[key1] = mean(values_list)

    return avg_per_object_type


def experiment_1(all_w, sigma, all_ps):
    results_all = {}
    for organization in all_ps.keys():
        results = _experiment_1_per_organization(all_ps[organization], _transform_sigma(sigma), all_w[organization])
        results_all[organization] = results
    return results_all


def _experiment_2_organization_documents_creation(ps):
    document1 = []
    document2 = []
    document3 = []
    document4 = []
    document5 = []
    document6 = []
    organization_results = {}
    for object_type in ps.keys():
        if object_type == 'bundles':
            signature = 'bundle'
            document1.append({signature: [ps[object_type][0]]})
            document2.append({signature: [ps[object_type][1]]})
            document3.append({signature: [ps[object_type][2]]})
            document4.append({signature: [ps[object_type][3]]})
            document5.append({signature: [ps[object_type][4]]})
            document6.append({signature: [ps[object_type][5]]})
        elif object_type == 'identities':
            signature = 'identity'
            document1.append({signature: [ps[object_type][0]]})
            document2.append({signature: [ps[object_type][1]]})
            document3.append({signature: [ps[object_type][2]]})
            document4.append({signature: [ps[object_type][3]]})
            document5.append({signature: [ps[object_type][4]]})
            document6.append({signature: [ps[object_type][5]]})
        elif object_type == 'indicators':
            signature = 'indicator'
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            document1.append({signature: ps[object_type][0:step]})
            document2.append({signature: ps[object_type][step:2 * step]})
            document3.append({signature: ps[object_type][2 * step:3 * step]})
            document4.append({signature: ps[object_type][3 * step:4 * step]})
            document5.append({signature: ps[object_type][4 * step:5 * step]})
            document6.append({signature: ps[object_type][5 * step:6 * step]})
        elif object_type == 'reports':
            signature = 'report'
            document1.append({signature: [ps[object_type][0]]})
            document2.append({signature: [ps[object_type][1]]})
            document3.append({signature: [ps[object_type][2]]})
            document4.append({signature: [ps[object_type][3]]})
            document5.append({signature: [ps[object_type][4]]})
            document6.append({signature: [ps[object_type][5]]})
        elif object_type == 'threat_actors':
            signature = 'threat-actor'
            document1.append({signature: [ps[object_type][0]]})
            document2.append({signature: [ps[object_type][1]]})
            document3.append({signature: [ps[object_type][0]]})
            document4.append({signature: [ps[object_type][1]]})
            document5.append({signature: [ps[object_type][0]]})
            document6.append({signature: [ps[object_type][1]]})
        elif object_type == 'vulnerabilities':
            signature = 'vulnerability'
            document1.append({signature: [ps[object_type][0]]})
            document2.append({signature: [ps[object_type][1]]})
            document3.append({signature: [ps[object_type][0]]})
            document4.append({signature: [ps[object_type][1]]})
            document5.append({signature: [ps[object_type][0]]})
            document6.append({signature: [ps[object_type][1]]})
        elif object_type == "url":
            signature = "url"
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            document1.append({signature: ps[object_type][0:step]})
            document2.append({signature: ps[object_type][step:2 * step]})
            document3.append({signature: ps[object_type][2 * step:3 * step]})
            document4.append({signature: ps[object_type][3 * step:4 * step]})
            document5.append({signature: ps[object_type][4 * step:5 * step]})
            document6.append({signature: ps[object_type][5 * step:6 * step]})
        elif object_type == "email-message":
            signature = "email-message"
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            document1.append({signature: ps[object_type][0:step]})
            document2.append({signature: ps[object_type][step:2 * step]})
            document3.append({signature: ps[object_type][2 * step:3 * step]})
            document4.append({signature: ps[object_type][3 * step:4 * step]})
            document5.append({signature: ps[object_type][4 * step:5 * step]})
            document6.append({signature: ps[object_type][5 * step:6 * step]})
        elif object_type == "ipv4-addr":
            signature = "ipv4-addr"
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            document1.append({signature: ps[object_type][0:step]})
            document2.append({signature: ps[object_type][step:2 * step]})
            document3.append({signature: ps[object_type][2 * step:3 * step]})
            document4.append({signature: ps[object_type][3 * step:4 * step]})
            document5.append({signature: ps[object_type][4 * step:5 * step]})
            document6.append({signature: ps[object_type][5 * step:6 * step]})
        elif object_type == 'domain-name':
            signature = 'domain-name'
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            document1.append({signature: ps[object_type][0:step]})
            document2.append({signature: ps[object_type][step:2 * step]})
            document3.append({signature: ps[object_type][2 * step:3 * step]})
            document4.append({signature: ps[object_type][3 * step:4 * step]})
            document5.append({signature: ps[object_type][4 * step:5 * step]})
            document6.append({signature: ps[object_type][5 * step:6 * step]})
        elif object_type == 'file':
            signature = 'file'
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            document1.append({signature: ps[object_type][0:step]})
            document2.append({signature: ps[object_type][step:2 * step]})
            document3.append({signature: ps[object_type][2 * step:3 * step]})
            document4.append({signature: ps[object_type][3 * step:4 * step]})
            document5.append({signature: ps[object_type][4 * step:5 * step]})
            document6.append({signature: ps[object_type][5 * step:6 * step]})
    organization_results['doc1'] = document1
    organization_results['doc2'] = document2
    organization_results['doc3'] = document3
    organization_results['doc4'] = document4
    organization_results['doc5'] = document5
    organization_results['doc6'] = document6

    return organization_results


def _experiment_2_per_organization(ps, sigma, weights):
    organization_results = {}
    organization_documents = _experiment_2_organization_documents_creation(ps)
    for key1 in organization_documents.keys():
        document_list = []
        w_list = []
        s_list = []
        for item in organization_documents[key1]:
            sigma_o = sigma[list(item.keys())[0]]
            weight_o = weights[list(item.keys())[0]]
            objects = item[list(item.keys())[0]]
            for object_t in objects:
                document_list.append(object_t[1])
                w_list.append(weight_o)
                s_list.append(sigma_o)
        wc_value = wc_metric(weights=w_list, delta_p=document_list, delta_s=s_list)
        organization_results[key1] = wc_value
    return organization_results


def experiment_2(all_w, sigma, all_ps):
    results_all = {}
    for organization in all_ps.keys():
        results = _experiment_2_per_organization(all_ps[organization], _transform_sigma(sigma), all_w[organization])
        results_all[organization] = results
    return results_all


def _experiment_3_organization_documents_creation(ps, org_id):
    document1 = []

    organization_results = {}
    for object_type in ps.keys():
        if object_type == 'bundles':
            signature = 'bundle'
            a = []
            a += org_id * [ps[object_type][0]]
            document1.append({signature: a})
        elif object_type == 'identities':
            signature = 'identity'
            a = []
            a += org_id * [ps[object_type][0]]
            document1.append({signature: a})
        elif object_type == 'indicators':
            signature = 'indicator'
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            a = []
            a += org_id * ps[object_type][0:step]
            document1.append({signature: a})
        elif object_type == 'reports':
            signature = 'report'
            a = []
            a += org_id * [ps[object_type][0]]
            document1.append({signature: a})
        elif object_type == 'threat_actors':
            signature = 'threat-actor'
            a = []
            a += org_id * [ps[object_type][0]]
            document1.append({signature: a})
        elif object_type == 'vulnerabilities':
            signature = 'vulnerability'
            a = []
            a += org_id * [ps[object_type][0]]
            document1.append({signature: a})
        elif object_type == "url":
            signature = "url"
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            a = []
            a += org_id * ps[object_type][0:step]
            document1.append({signature: a})
        elif object_type == "email-message":
            signature = "email-message"
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            a = []
            a += org_id * ps[object_type][0:step]
            document1.append({signature: a})
        elif object_type == "ipv4-addr":
            signature = "ipv4-addr"
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            a = []
            a += org_id * ps[object_type][0:step]
            document1.append({signature: a})
        elif object_type == 'domain-name':
            signature = 'domain-name'
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            a = []
            a += org_id * ps[object_type][0:step]
            document1.append({signature: a})
        elif object_type == 'file':
            signature = 'file'
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            a = []
            a += org_id * ps[object_type][0:step]
            document1.append({signature: a})
    organization_results['doc1'] = document1
    return organization_results


def _experiment_3_per_organization(ps, sigma, weights, org_id):
    organization_results = {}
    organization_documents = _experiment_3_organization_documents_creation(ps, org_id)
    for key1 in organization_documents.keys():
        document_list = []
        w_list = []
        s_list = []
        for item in organization_documents[key1]:
            sigma_o = sigma[list(item.keys())[0]]
            weight_o = weights[list(item.keys())[0]]
            objects = item[list(item.keys())[0]]
            for object_t in objects:
                document_list.append(object_t[1])
                w_list.append(weight_o)
                s_list.append(sigma_o)
        start_time = time.time()
        start_time_cpu = time.process_time()
        wc_value = wc_metric(weights=w_list, delta_p=document_list, delta_s=s_list)
        end_time_cpu = time.process_time()
        end_time = time.time()
        organization_results[key1] = {'value': wc_value, 'time': end_time - start_time,
                                      'cpu_time': end_time_cpu - start_time_cpu}
    return organization_results


def experiment_3(all_w, sigma, all_ps):
    results_all = {}
    for organization in all_ps.keys():
        results = _experiment_3_per_organization(all_ps[organization], _transform_sigma(sigma), all_w[organization],
                                                 int(organization.replace("C", "")))
        results_all[organization] = results
    return results_all


def _experiment_4_organization_documents_creation(ps):
    document1 = []
    document2 = []
    document3 = []
    document4 = []
    document5 = []
    document6 = []
    organization_results = {}
    for object_type in ps.keys():
        if object_type == 'bundles':
            signature = 'bundle'
            document1.append({signature: [ps[object_type][0]]})
            document2.append({signature: [ps[object_type][1]]})
            document3.append({signature: [ps[object_type][2]]})
            document4.append({signature: [ps[object_type][3]]})
            document5.append({signature: [ps[object_type][4]]})
            document6.append({signature: [ps[object_type][5]]})
        elif object_type == 'identities':
            signature = 'identity'
            document1.append({signature: [ps[object_type][0]]})
            document2.append({signature: [ps[object_type][1]]})
            document3.append({signature: [ps[object_type][2]]})
            document4.append({signature: [ps[object_type][3]]})
            document5.append({signature: [ps[object_type][4]]})
            document6.append({signature: [ps[object_type][5]]})
        elif object_type == 'indicators':
            signature = 'indicator'
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            document1.append({signature: ps[object_type][0:step]})
            document2.append({signature: ps[object_type][step:2 * step]})
            document3.append({signature: ps[object_type][2 * step:3 * step]})
            document4.append({signature: ps[object_type][3 * step:4 * step]})
            document5.append({signature: ps[object_type][4 * step:5 * step]})
            document6.append({signature: ps[object_type][5 * step:6 * step]})
        elif object_type == 'reports':
            signature = 'report'
            document1.append({signature: [ps[object_type][0]]})
            document2.append({signature: [ps[object_type][1]]})
            document3.append({signature: [ps[object_type][2]]})
            document4.append({signature: [ps[object_type][3]]})
            document5.append({signature: [ps[object_type][4]]})
            document6.append({signature: [ps[object_type][5]]})
        elif object_type == 'threat_actors':
            signature = 'threat-actor'
            document1.append({signature: [ps[object_type][0]]})
            document2.append({signature: [ps[object_type][1]]})
            document3.append({signature: [ps[object_type][0]]})
            document4.append({signature: [ps[object_type][1]]})
            document5.append({signature: [ps[object_type][0]]})
            document6.append({signature: [ps[object_type][1]]})
        elif object_type == 'vulnerabilities':
            signature = 'vulnerability'
            document1.append({signature: [ps[object_type][0]]})
            document2.append({signature: [ps[object_type][1]]})
            document3.append({signature: [ps[object_type][0]]})
            document4.append({signature: [ps[object_type][1]]})
            document5.append({signature: [ps[object_type][0]]})
            document6.append({signature: [ps[object_type][1]]})
        elif object_type == "url":
            signature = "url"
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            document1.append({signature: ps[object_type][0:step]})
            document2.append({signature: ps[object_type][step:2 * step]})
            document3.append({signature: ps[object_type][2 * step:3 * step]})
            document4.append({signature: ps[object_type][3 * step:4 * step]})
            document5.append({signature: ps[object_type][4 * step:5 * step]})
            document6.append({signature: ps[object_type][5 * step:6 * step]})
        elif object_type == "email-message":
            signature = "email-message"
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            document1.append({signature: ps[object_type][0:step]})
            document2.append({signature: ps[object_type][step:2 * step]})
            document3.append({signature: ps[object_type][2 * step:3 * step]})
            document4.append({signature: ps[object_type][3 * step:4 * step]})
            document5.append({signature: ps[object_type][4 * step:5 * step]})
            document6.append({signature: ps[object_type][5 * step:6 * step]})
        elif object_type == "ipv4-addr":
            signature = "ipv4-addr"
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            document1.append({signature: ps[object_type][0:step]})
            document2.append({signature: ps[object_type][step:2 * step]})
            document3.append({signature: ps[object_type][2 * step:3 * step]})
            document4.append({signature: ps[object_type][3 * step:4 * step]})
            document5.append({signature: ps[object_type][4 * step:5 * step]})
            document6.append({signature: ps[object_type][5 * step:6 * step]})
        elif object_type == 'domain-name':
            signature = 'domain-name'
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            document1.append({signature: ps[object_type][0:step]})
            document2.append({signature: ps[object_type][step:2 * step]})
            document3.append({signature: ps[object_type][2 * step:3 * step]})
            document4.append({signature: ps[object_type][3 * step:4 * step]})
            document5.append({signature: ps[object_type][4 * step:5 * step]})
            document6.append({signature: ps[object_type][5 * step:6 * step]})
        elif object_type == 'file':
            signature = 'file'
            cardinality = len(ps[object_type])
            step = ceil(cardinality / 6)
            document1.append({signature: ps[object_type][0:step]})
            document2.append({signature: ps[object_type][step:2 * step]})
            document3.append({signature: ps[object_type][2 * step:3 * step]})
            document4.append({signature: ps[object_type][3 * step:4 * step]})
            document5.append({signature: ps[object_type][4 * step:5 * step]})
            document6.append({signature: ps[object_type][5 * step:6 * step]})
    organization_results['doc1'] = document1
    organization_results['doc2'] = document2
    organization_results['doc3'] = document3
    organization_results['doc4'] = document4
    organization_results['doc5'] = document5
    organization_results['doc6'] = document6

    return organization_results


def _experiment_4_per_organization(ps, sigma, weights):
    organization_results = {}
    organization_documents = _experiment_4_organization_documents_creation(ps)
    for key1 in organization_documents.keys():
        document_list = []
        w_list = []
        s_list = []
        for item in organization_documents[key1]:
            sigma_o = sigma[list(item.keys())[0]]
            weight_o = weights[list(item.keys())[0]]
            objects = item[list(item.keys())[0]]
            for object_t in objects:
                document_list.append(object_t[1])
                w_list.append(weight_o)
                s_list.append(sigma_o)
        c_value = c_metric(delta_p=document_list, delta_s=s_list)
        organization_results[key1] = c_value
    return organization_results


def experiment_4(all_w, sigma, all_ps):
    results_all = {}
    for organization in all_ps.keys():
        results = _experiment_4_per_organization(all_ps[organization], _transform_sigma(sigma), all_w[organization])
        results_all[organization] = results
    return results_all


def wc_main():
    all_w, sigma, all_ps = load_data()
    data_1 = experiment_1(all_w, sigma, all_ps)
    print(data_1)
    write_json(data1=data_1, filepath='experiment_1_results.json')
    data_2 = experiment_2(all_w, sigma, all_ps)
    print(data_2)
    write_json(data1=data_2, filepath='experiment_2_results.json')
    data_3 = experiment_3(all_w, sigma, all_ps)
    print(data_3)
    write_json(data1=data_3, filepath='experiment_3_results.json')
    data_4 = experiment_4(all_w, sigma, all_ps)
    print(data_4)
    write_json(data1=data_4, filepath='experiment_4_results.json')


if __name__ == "__main__":
    wc_main()
