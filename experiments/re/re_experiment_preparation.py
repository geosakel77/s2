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
import random
from math import ceil
from random import shuffle


def read_json(filepath):
    data1 = _load(filepath)
    return data1


def list_filenames(path):
    return os.listdir(path)


def write_json(data1, filepath):
    with open(filepath, 'w', encoding='utf-8') as jsonfile:
        json.dump(data1, jsonfile)
        jsonfile.close()

def _load(path):
    with open(path, 'r', encoding='utf-8') as jsonfile:
        data = json.load(jsonfile)
        jsonfile.close()
    return data

def load_data():
    all_delta = _load('all_organizations_delta.json')
    all_giota = _load('all_organizations_giota.json')
    all_pu = _load('all_organizations_pu.json')
    return all_delta, all_giota, all_pu

def select_object(bunch):
    objects_list = []
    max_number = ceil(len(bunch) / 10)
    count = 0
    while len(objects_list) <= max_number:
        flag = random.random()
        if flag >= 0.5:
            objects_list.append(bunch.pop())
            count += 1
            shuffle(bunch)
    return objects_list


def select_objects(bunch, name):
    objects = {}
    objects[name] = select_object(bunch)
    return objects


def create_pui(alerts, reports):
    organisation_pui = [select_objects(alerts, 'alerts'), select_objects(reports, 'reports')]
    return organisation_pui


def create_all_pui():
    all_organizations_pui = {}
    for i in range(1, 11):
        alerts = list_filenames('../../datasets/text_files/alerts')
        reports = list_filenames('../../datasets/text_files/reports')
        print("Alerts: {}".format(len(alerts)))
        print("Reports: {}".format(len(reports)))
        organization_pui = create_pui(alerts=alerts, reports=reports)
        print("Create Pu for organization C{}".format(i))
        write_json(organization_pui, 'Pu_C' + str(i) + '.json')
        all_organizations_pui['C' + str(i)] = organization_pui
    return all_organizations_pui


def create_giota(cpes, rank):
    cpes_list = []
    for i in range(0, rank * 10000):
        seed = random.randint(0, 945526)
        cpes_list.append(cpes[seed])
    print(len(cpes_list))
    return cpes_list


def create_all_organizations_giota():
    all_organizations_giota = {}
    for i in range(1, 11):
        cpes = _load('../../datasets/cpes.json')
        print("CPEs: {}".format(len(cpes)))
        organization_giota = create_giota(cpes, i)
        print("Create giota for organization C{}".format(i))
        write_json(organization_giota, 'Giota_C' + str(i) + '.json')
        all_organizations_giota['C' + str(i)] = organization_giota
    return all_organizations_giota


def create_delta(delta, rank):
    delta_list = []
    delta_keys_list= list(delta.keys())
    for i in range(0, rank):
        seed = random.randint(0,25)
        delta_list.append({delta_keys_list[seed]:delta[delta_keys_list[seed]]})
    return delta_list

def create_all_organizations_delta():
    all_organizations_delta = {}
    for i in range(1, 11):
        delta = _load('../../datasets/delta.json')
        print("DITs: {}".format(len(list(delta.keys()))))
        print("Create delta for organization C{}".format(i))
        organization_delta = create_delta(delta, i)
        all_organizations_delta['C' + str(i)] = organization_delta
    return all_organizations_delta

def _tranform_giota(giota):
    tranformed_giota=[]
    print(len(giota))
    return tranformed_giota

def transform_all_organizations_giota(all_giota):
    all_organizations_transformed_giota ={}
    for organization in all_giota.keys():
        transformed_organization_giota=_tranform_giota(all_giota[organization])
        all_organizations_transformed_giota[organization]=transformed_organization_giota
    return all_organizations_transformed_giota


if __name__ == "__main__":
    all_delta, all_giota, all_pu =load_data()
    print(transform_all_organizations_giota(all_giota))
    #write_json(create_all_organizations_giota(), 'all_organizations_giota.json')
    #write_json(create_all_organizations_delta(),'all_organizations_delta.json')
    print(all_giota['C1'])
