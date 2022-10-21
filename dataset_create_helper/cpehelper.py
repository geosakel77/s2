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

import xml.etree.ElementTree as ET
import json



def store_cpes(transformed_delta):
    with open("../datasets/cpes.json", 'w') as out:
        json.dump(transformed_delta, out)
        out.close()

def export_cpes(library):
    namespaces = {"cpe-23": "http://scap.nist.gov/schema/cpe-extension/2.3"}
    parsed_library = ET.parse(library)
    root = parsed_library.getroot()
    elements = list(root)
    cpeslist=[]
    for cpe_item in elements:
        cpe_dictionary={}
        cpe23_element = cpe_item.find("cpe-23:cpe23-item", namespaces)
        if cpe23_element is not None:
            cpe23_list = cpe23_element.get('name').split(":")
            if cpe23_list[2]=="a":
                cpe_dictionary["part"]="applications"
            elif cpe23_list[2]=="o":
                cpe_dictionary["part"]="operating systems"
            elif cpe23_list[2]=="h":
                cpe_dictionary["part"] = "hardware devices"
            if cpe23_list[3]=="*":
                cpe_dictionary["vendor"]=""
            else:
                cpe_dictionary["vendor"]=cpe23_list[3]
            if cpe23_list[4]=="*":
                cpe_dictionary["product"]=""
            else:
                cpe_dictionary["product"]=cpe23_list[4]
            if cpe23_list[5]=="*":
                cpe_dictionary["version"]=""
            else:
                cpe_dictionary["version"]=cpe23_list[5]
            if cpe23_list[6]=="*":
                cpe_dictionary["update"]=""
            else:
                cpe_dictionary["update"]=cpe23_list[6]
            if cpe23_list[7]=="*":
                cpe_dictionary["edition"]=""
            else:
                cpe_dictionary["edition"]=cpe23_list[7]
            if cpe23_list[8]=="*":
                cpe_dictionary["language"]=""
            else:
                cpe_dictionary["language"]=cpe23_list[8]
            if cpe23_list[9]=="*":
                cpe_dictionary["sw_edition"]=""
            else:
                cpe_dictionary["sw_edition"]=cpe23_list[9]
            if cpe23_list[10]=="*":
                cpe_dictionary["target_sw"]=""
            else:
                cpe_dictionary["target_sw"]=cpe23_list[10]
            if cpe23_list[11]=="*":
                cpe_dictionary["target_hw"]=""
            else:
                cpe_dictionary["target_hw"]=cpe23_list[11]
            if cpe23_list[11] == "*":
                cpe_dictionary["other"] = ""
            else:
                cpe_dictionary["other"] = cpe23_list[12]
            cpeslist.append(cpe_dictionary)
    return cpeslist


if __name__=="__main__":
    store_cpes(export_cpes("../raw_data/official-cpe-dictionary_v2.3.xml"))





