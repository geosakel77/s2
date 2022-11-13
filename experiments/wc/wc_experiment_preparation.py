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
import os
import random
from math import ceil
from random import shuffle

delta_path = "../../datasets/sigma_stixv2.json"

existed_objects = ['report', 'vulnerability', 'threat-actor', 'identity', 'indicator', 'domain-name', 'file',
                   'email-message', 'url', 'ipv4-addr', 'bundle']


def read_json(filepath):
    data1 = _load(filepath)
    return data1


def write_json(data1, filepath):
    with open(filepath, 'w', encoding='utf-8') as jsonfile:
        json.dump(data1, jsonfile)
        jsonfile.close()


def list_filenames(path):
    return os.listdir(path)


def wi_generator():
    return random.random()


def create_w():
    delta = read_json(delta_path)
    all_organizations_w = {}
    total_keys = []
    for key1 in delta.keys():
        total_keys.append(delta[key1].keys())
    flatten_list = list(itertools.chain(*total_keys))
    for i in range(1, 11):
        organization_w = {}
        for key1 in flatten_list:
            if key1 in existed_objects:
                organization_w[key1] = wi_generator()
            else:
                organization_w[key1] = 0
        all_organizations_w['C' + str(i)] = organization_w
    return all_organizations_w


def select_object(bunch):
    objects_list = []
    max_number = ceil(len(bunch) / 10)
    count = 0
    while len(objects_list) <= max_number:
        flag = random.random()
        if flag >= 0.5:
            objects_list.append(bunch.pop())
            count += 1
            print(count)
            shuffle(bunch)
    return objects_list


def select_objects(bunch, name):
    objects = {}
    if name == 'observables':
        ipv4 = []
        url = []
        domain_name = []
        file = []
        email = []
        for observable in bunch:
            data1 = read_json(os.path.join('../../datasets/stixv2/observables', observable))
            if data1['type'] == 'ipv4-addr':
                ipv4.append(observable)
            elif data1['type'] == 'domain-name':
                domain_name.append(observable)
            elif data1['type'] == 'email-message':
                email.append(observable)
            elif data1['type'] == 'url':
                url.append(observable)
            elif data1['type'] == 'file':
                file.append(observable)
        print("Create:{}".format(name))
        objects[name] = {'ipv4-addr': select_object(ipv4), 'domain-name': select_object(domain_name),
                         'email-message': select_object(email), 'url': select_object(url), 'file': select_object(file)}
    else:
        print("Create:{}".format(name))
        objects[name] = select_object(bunch)
    return objects


def create_psi(bundles, identities, indicators, observables, reports, threat_actors, vulnerabilities):
    organisation_psi = [select_objects(bundles, 'bundles'), select_objects(identities, 'identities'),
                        select_objects(indicators, 'indicators'), select_objects(observables, 'observables'),
                        select_objects(reports, 'reports'), select_objects(threat_actors, 'threat_actors'),
                        select_objects(vulnerabilities, 'vulnerabilities')]
    return organisation_psi


def create_all_psi():
    all_organizations_psi = {}
    for i in range(1, 11):
        bundles = list_filenames('../../datasets/stixv2/bundles')
        identities = list_filenames('../../datasets/stixv2/identities')
        indicators = list_filenames('../../datasets/stixv2/indicators')
        observables = list_filenames('../../datasets/stixv2/observables')
        reports = list_filenames('../../datasets/stixv2/reports')
        threat_actors = list_filenames('../../datasets/stixv2/threat_actors')
        vulnerabilities = list_filenames('../../datasets/stixv2/vulnerabilities')
        print("Bundles: {}".format(len(bundles)))
        print("Identities: {}".format(len(identities)))
        print("Indicators: {}".format(len(indicators)))
        print("Observables: {}".format(len(observables)))
        print("Reports: {}".format(len(reports)))
        print("Threat Actors: {}".format(len(threat_actors)))
        print("Vulnerabilities: {}".format(len(vulnerabilities)))
        organization_psi = create_psi(bundles=bundles, identities=identities, indicators=indicators,
                                      observables=observables,
                                      reports=reports, threat_actors=threat_actors,
                                      vulnerabilities=vulnerabilities)
        print("Create PS for organization C{}".format(i))
        write_json(organization_psi, 'Ps_C' + str(i) + '.json')
        all_organizations_psi['C' + str(i)] = organization_psi

    return all_organizations_psi


def load_data():
    all_w = _load('all_organizations_w.json')
    sigma = _load('../../datasets/sigma_stixv2.json')
    all_ps = _load('all_organisations_ps.json')
    return all_w, sigma, all_ps


def _load(path):
    with open(path, 'r', encoding='utf-8') as jsonfile:
        data = json.load(jsonfile)
        jsonfile.close()
    return data


def _count_bundle_identities_properties(data):
    count_properties = 0
    for key in data.keys():
        if key != 'spec_version':
            if key != 'labels':
                if key != 'created':
                    if key != 'modified':
                        if len(data[key]) > 0:
                            count_properties += 1
    return count_properties


def _count_indicators_properties(data):
    count_properties = 0
    for key in data.keys():
        if key != 'spec_version':
            if key != 'labels':
                if key != 'created':
                    if key != 'modified':
                        if len(data[key]) > 0:
                            count_properties += 1
    return count_properties


def _count_reports_properties(data):
    count_properties = 0
    for key in data.keys():
        if key != 'spec_version':
            if key != 'labels':
                if key != 'created_by_ref':
                    if key != 'created':
                        if key != 'modified':
                            if len(data[key]) > 0:
                                count_properties += 1
    return count_properties


def _count_threat_actors_properties(data):
    count_properties = 0
    for key in data.keys():
        if key != 'spec_version':
            if key != 'labels':
                if key != 'created_by_ref':
                    if key != 'created':
                        if key != 'modified':
                            if key != 'external_references':
                                if len(data[key]) > 0:
                                    count_properties += 1
    return count_properties


def _count_vulnerabilities_properties(data):
    count_properties = 0
    for key in data.keys():
        if key != 'spec_version':
            if key != 'created':
                if key != 'modified':
                    if key != 'external_references':
                        if len(data[key]) > 0:
                            count_properties += 1
    return count_properties


def _count_ipv4_domain_name_email_message_url_file_properties(data):
    count_properties = 0
    for key in data.keys():
        if key != 'spec_version':
            if isinstance(data[key], bool):
                count_properties += 1
            else:
                if len(data[key]) > 0:
                    count_properties += 1
    return count_properties


def count_complete_properties(filename, object_type, sigma, path='../../datasets/stixv2', observable_type=None):
    path = os.path.join(path, object_type, filename)
    data = _load(path)
    count_properties = None
    if object_type == 'bundles':
        count_properties = _count_bundle_identities_properties(data)
        if count_properties > sigma['common']['bundle'][1]:
            count_properties = -1
    elif object_type == 'identities':
        count_properties = _count_bundle_identities_properties(data)
        if count_properties > sigma['sdos']['identity'][1]:
            count_properties = -1
    elif object_type == 'indicators':
        count_properties = _count_indicators_properties(data)
        if count_properties > sigma['sdos']['indicator'][1]:
            count_properties = -1
    elif object_type == 'reports':
        count_properties = _count_reports_properties(data)
        if count_properties > sigma['sdos']['report'][1]:
            count_properties = -1
    elif object_type == 'threat_actors':
        count_properties = _count_threat_actors_properties(data)
        if count_properties > sigma['sdos']['threat-actor'][1]:
            count_properties = -1
    elif object_type == 'vulnerabilities':
        count_properties = _count_vulnerabilities_properties(data)
        if count_properties > sigma['sdos']['vulnerability'][1]:
            count_properties = -1
    elif object_type == 'observables':
        if observable_type == 'ipv4-addr':
            count_properties = _count_ipv4_domain_name_email_message_url_file_properties(data)
            if count_properties > sigma['observables']['ipv4-addr'][1]:
                count_properties = -1
        elif observable_type == 'domain-name':
            count_properties = _count_ipv4_domain_name_email_message_url_file_properties(data)
            if count_properties > sigma['observables']['domain-name'][1]:
                count_properties = -1
        elif observable_type == 'email-message':
            count_properties = _count_ipv4_domain_name_email_message_url_file_properties(data)
            if count_properties > sigma['observables']['email-message'][1]:
                count_properties = -1
        elif observable_type == 'url':
            count_properties = _count_ipv4_domain_name_email_message_url_file_properties(data)
            if count_properties > sigma['observables']['url'][1]:
                count_properties = -1
        elif observable_type == 'file':
            count_properties = _count_ipv4_domain_name_email_message_url_file_properties(data)
            if count_properties > sigma['observables']['file'][1]:
                count_properties = -1
    else:
        pass
    return count_properties


def count_organization_complete_properties(organization_ps, sigma):
    counters_dict = {}
    for object_type in organization_ps:
        counters_key = None
        objects_counters_list = []
        print("Start counting:{}".format(list(object_type.keys())[0]))
        for key in object_type.keys():
            if key != 'observables':
                for item in object_type[key]:
                    counter = count_complete_properties(item, key, sigma)
                    if counter is not None:
                        objects_counters_list.append((item.split(".")[0], counter))
                counters_key = key
                counters_dict[counters_key] = objects_counters_list
            else:
                observables_keys = object_type[key].keys()
                observables = object_type[key]
                for observable_key in observables_keys:
                    for item in observables[observable_key]:
                        counter = count_complete_properties(filename=item, object_type=key, sigma=sigma,
                                                            observable_type=observable_key)
                        if counter is not None:
                            objects_counters_list.append((item.split(".")[0], counter))
                    counters_key = observable_key
                    counters_dict[counters_key] = objects_counters_list
    return counters_dict

def count_all_organizations():
    all_w, sigma, all_ps = load_data()
    all_organizations_ps_counted={}
    for organization in all_ps.keys():
        print("Count Ps of organization:{}".format(organization))
        all_organizations_ps_counted[organization]=count_organization_complete_properties(all_ps[organization], sigma)

    write_json(all_organizations_ps_counted,'all_organizations_ps_counted.json')

if __name__ == "__main__":
    count_all_organizations()
