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
import os,json
from stix2.v21 import URL,DomainName,File,IPv4Address, EmailMessage, EmailAddress
from hashlib import sha1


class STIXv2Manager:
    def __init__(self,otx_path="../datasets/stixv2/otx",observables_path='../datasets/stixv2/observables',sdos_path='../datasets/stixv2/sdos'):
        self.otx_path =otx_path
        self.observables_path=observables_path
        self.sdos_path = sdos_path

    def _get_otx_files_paths(self):
        otx_files = [os.path.join(self.otx_path, file) for file in os.listdir(self.otx_path)]
        return otx_files

    def write_observables(self):
        for observable in self.create_stixv2_observables():
            serialized_observable=observable.serialize(pretty=True)
            filenameprefix = sha1(serialized_observable.encode()).hexdigest()
            filename = filenameprefix + ".json"
            filepath = os.path.join(self.observables_path, filename)
            self._write_observable(observable,filepath)
            print("Observable {} has written.".format(filenameprefix))

    def _write_observable(self,observable,observable_filename):
        with open(observable_filename, 'w',encoding='utf-8') as out:
            observable.fp_serialize(out, pretty=True)
            out.close()

    def create_stixv2_observables(self):
        observables =[]
        serialized_observables = self._get_serialized_observables()
        for serialized_observable in serialized_observables:
            observables.append(self._create_object(serialized_observable))
        return observables

    def _get_serialized_observables(self):
        serialized_observables=[]
        for indicator in self._get_indicators():
            serialized_observable= indicator['pattern']
            if 'rule' not in serialized_observable:
                a = serialized_observable.replace("[", "")
                b = a.replace("]", "")
                serialized_observables.append(b)
        return serialized_observables

    def _get_indicators(self):
        indicators = []
        for stixv2file in self._get_otx_files_paths():
            with open(stixv2file, 'r') as jsonfile:
                stixv2 = json.load(jsonfile)
                jsonfile.close()
            for object in stixv2['objects']:
                object_type = object["id"].split("--")[0]
                if object_type == 'indicator':
                    indicators.append(object)
        return indicators

    def _create_object(self,serialized_observable):
        observable=None
        if "url" in serialized_observable:
            observable = URL(value=serialized_observable.split("=")[1].strip().replace("'",""))
        elif "domain" in serialized_observable:
            observable = DomainName(value=serialized_observable.split("=")[1].strip().replace("'",""))
        elif "ipv4" in serialized_observable:
            observable = IPv4Address(value=serialized_observable.split("=")[1].strip().replace("'",""))
        elif "file" in serialized_observable:
            if 'MD5'in serialized_observable:
                observable = File(hashes={'MD5':serialized_observable.split("=")[1].strip().replace("'","")})
            elif 'SHA-256' in serialized_observable:
                observable = File(hashes={'SHA-256':serialized_observable.split("=")[1].strip().replace("'","")})
            elif "SHA-1" in serialized_observable:
                observable = File(hashes={'SHA-1':serialized_observable.split("=")[1].strip().replace("'","")})
            else:
                print("Algorithm Type not created")
        elif "email" in serialized_observable:
            emailaddress= EmailAddress(value=serialized_observable.split("=")[1].strip().replace("'",""))
            observable = EmailMessage(from_ref=emailaddress,is_multipart=False)
        else:
            print("Observable Type not created")
            print(serialized_observable)
        return observable

    def get_observable(self):
        count_bundles = 0
        objects_types = []
        objects_per_type = {}
        observable_types=[]
        objects_per_observable_type={}
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
                if object_type =='indicator':
                    object_observable= object['pattern']
                    if 'rule'not in object_observable:
                        a=object_observable.replace("[","")
                        b=a.replace("]", "")
                        observable_type = b.split("=")[0].strip()
                        if observable_type not in observable_types:
                            observable_types.append(observable_type)
                            objects_per_observable_type[observable_type]=0
                        objects_per_observable_type[observable_type]+=1
                objects_per_type[object_type] += 1
        temp_text = ""
        temp_text_observable="Observables:\n"
        for observable_type in observable_types:
            temp_text_observable = temp_text_observable + "{} objects number: {}\n".format(observable_type, objects_per_observable_type[observable_type])

        for object_type in objects_types:
            temp_text = temp_text + "{} objects number: {}\n".format(object_type, objects_per_type[object_type])
        text_formated = "Stixv2 files number: {}\n" \
                        "Bundle objects number: {}\n" \
                        "{}" \
                        "{}".format(len(self._get_otx_files_paths()), count_bundles, temp_text,temp_text_observable)
        return text_formated


if __name__ == '__main__':
    STIXv2Manager().write_observables()
