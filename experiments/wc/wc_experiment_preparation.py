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
    with open(filepath, 'r', encoding='Utf-8') as jsonfile:
        data = json.load(jsonfile)
        jsonfile.close()
    return data


def write_json(data, filepath):
    with open(filepath, 'w', encoding='utf-8') as jsonfile:
        json.dump(data, jsonfile)
        jsonfile.close()


def list_filenames(path):
    return os.listdir(path)


def wi_generator():
    return random.random()


def create_w():
    delta = read_json(delta_path)
    all_organizations_w = {}
    total_keys = []
    for key in delta.keys():
        total_keys.append(delta[key].keys())
    flatten_list = list(itertools.chain(*total_keys))
    for i in range(1, 11):
        organization_w = {}
        for key in flatten_list:
            if key in existed_objects:
                organization_w[key] = wi_generator()
            else:
                organization_w[key] = 0
        all_organizations_w['C' + str(i)] = organization_w
    return all_organizations_w


def select_object(bunch):
    objects_list = []
    max_number = ceil(len(bunch) / 10)
    count=0
    while len(objects_list) <= max_number:
        flag = random.random()
        if flag >= 0.5:
            objects_list.append(bunch.pop())
            count+=1
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
            data = read_json(os.path.join('../../datasets/stixv2/observables', observable))
            if data['type'] == 'ipv4-addr':
                ipv4.append(observable)
            elif data['type'] == 'domain-name':
                domain_name.append(observable)
            elif data['type'] == 'email-message':
                email.append(observable)
            elif data['type'] == 'url':
                url.append(observable)
            elif data['type'] == 'file':
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
        organization_psi = create_psi(bundles=bundles, identities=identities, indicators=indicators, observables=observables,
                                      reports=reports, threat_actors=threat_actors,
                                      vulnerabilities=vulnerabilities)
        print("Create PS for organization C{}".format(i))
        write_json(organization_psi,'Ps_C'+str(i)+'.json')
        all_organizations_psi['C' + str(i)] = organization_psi

    return all_organizations_psi


if __name__ == "__main__":
    # write_json(create_w(),'all_organizations_w.json')
    # print(len(list_filenames('../../datasets/stixv2/observables')))
    data=create_all_psi()
    write_json(data,'all_organisations_ps.json')
    print(data)
