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


def list_sdos(sdos_path="../raw_data/stixv2_schemas/sdos"):
    sdos_list = os.listdir(sdos_path)
    sdos_cleaned = [s.split(".")[0] for s in sdos_list]
    return sdos_cleaned


def list_sros(sros_path="../raw_data/stixv2_schemas/sros"):
    sros_list = os.listdir(sros_path)
    sros_cleaned = [s.split(".")[0] for s in sros_list]
    return sros_cleaned


def list_observables(observables_path="../raw_data/stixv2_schemas/observables"):
    observables_list = os.listdir(observables_path)
    observables_cleaned = [s.split(".")[0] for s in observables_list]
    return observables_cleaned

def list_common(common_path="../raw_data/stixv2_schemas/common"):
    common_list = os.listdir(common_path)
    common_cleaned = [s.split(".")[0] for s in common_list]
    return common_cleaned

def extract_objdt():
    objdt = {}
    objdt["sdos"] = list_sdos()
    objdt["observables"] = list_observables()
    objdt["common"] = list_common()
    objdt["sros"] = list_sros()
    return objdt


def read_schema(filepath):
    with open(filepath, "r", encoding='utf-8', ) as schema_file:
        schema_dictionary = json.load(schema_file)
        schema_file.close()
    return schema_dictionary


def count_max_properties_stixv2(schema_dictionary, key_1="allOf", key_2="properties", key_3="minProperties"):
    keys = schema_dictionary.keys()
    if key_2 in keys:
        mpr = (("alpha", 0), len(schema_dictionary[key_2].keys()))
    elif key_1 in keys:
        if len(schema_dictionary[key_1]) > 1:
            mpr_estimation = len(schema_dictionary[key_1][1][key_2].keys())
            mpr = (("alpha", 0), mpr_estimation)
        else:
            mpr = (("alpha", 0), 0)
    elif key_3 in keys:
        mpr = (("alpha", 0), schema_dictionary[key_3])
    else:
        mpr = (("alpha", 0), 0)
    return mpr

def count_mpr_of_all_objdt():
    objdt = extract_objdt()
    objdt_dictionary = {}
    for key in objdt.keys():
        category = {}
        for objdi in objdt[key]:
            path = os.path.join("../raw_data/stixv2_schemas", key, objdi + "." + "json")
            schema_dictionary = read_schema(path)
            mpr = count_max_properties_stixv2(schema_dictionary)
            category[objdi] = mpr
        objdt_dictionary[key] = category
    return objdt_dictionary

def store_sigma(transformed_sigma):
    with open("../datasets/sigma_stixv2.json", 'w') as out:
        json.dump(transformed_sigma, out)
        out.close()


if __name__ == "__main__":
    store_sigma(count_mpr_of_all_objdt())
