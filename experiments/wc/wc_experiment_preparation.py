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
import random

delta_path = "../../datasets/sigma_stixv2.json"

existed_objects = ['report', 'vulnerability', 'threat-actor', 'identity', 'indicator', 'domain-name', 'file',
                   'email-message', 'url', 'ipv4-addr', 'bundle']


def read_json(filepath):
    with open(filepath, 'r', encoding='Utf-8') as jsonfile:
        data = json.load(jsonfile)
        jsonfile.close()
    return data


def write_json(data,filepath):
    with open(filepath, 'w', encoding='utf-8') as jsonfile:
        json.dump(data, jsonfile)
        jsonfile.close()


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


if __name__ == "__main__":
    #write_json(create_w(),'all_organizations_w.json')
    pass
