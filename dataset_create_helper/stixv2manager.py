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
from hashlib import sha1

from stix2 import parse
from stix2.v21 import URL, DomainName, File, IPv4Address, EmailMessage, EmailAddress, ThreatActor, ExternalReference


class STIXv2Manager:
    def __init__(self, otx_path="../datasets/stixv2/otx", observables_path='../datasets/stixv2/observables',
                 bundles_path='../datasets/stixv2/bundles', identities_path="../datasets/stixv2/identities",
                 indicators_path="../datasets/stixv2/indicators", reports_path="../datasets/stixv2/reports",
                 threat_actors_path="../datasets/stixv2/threat_actors",
                 vulnerabilities_path="../datasets/stixv2/vulnerabilities"):
        self.otx_path = otx_path
        self.observables_path = observables_path
        self.bundles_path = bundles_path
        self.identities_path = identities_path
        self.indicators_path = indicators_path
        self.reports_path = reports_path
        self.threat_actors_path = threat_actors_path
        self.vulnerabilities_path = vulnerabilities_path

    def _get_otx_files_paths(self):
        otx_files = [os.path.join(self.otx_path, file) for file in os.listdir(self.otx_path)]
        return otx_files

    def write_observables(self):
        for observable in self.create_stixv2_observables():
            serialized_observable = observable.serialize(pretty=True)
            filenameprefix = sha1(serialized_observable.encode()).hexdigest()
            filename = filenameprefix + ".json"
            filepath = os.path.join(self.observables_path, filename)
            # noinspection PyTypeChecker
            self._write_object(observable, filepath)
            print("Observable {} has written.".format(filenameprefix))

    def _write_object(self, stixobject, stixobject_filename):
        with open(stixobject_filename, 'w', encoding='utf-8') as out:
            stixobject.fp_serialize(out, pretty=True)
            out.close()

    def create_stixv2_observables(self):
        observables = []
        serialized_observables = self._get_serialized_observables()
        for serialized_observable in serialized_observables:
            observables.append(self._create_observable(serialized_observable))
        return observables

    def _get_serialized_observables(self):
        serialized_observables = []
        for indicator in self._get_indicators():
            serialized_observable = indicator['pattern']
            if 'rule' not in serialized_observable:
                a = serialized_observable.replace("[", "")
                b = a.replace("]", "")
                serialized_observables.append(b)
        return serialized_observables

    def write_indicators(self):
        for indicators_tex in self._get_indicators():
            indicator = parse(indicators_tex)
            serialized_indicator = indicator.serialize(pretty=True)
            filenameprefix = sha1(serialized_indicator.encode()).hexdigest()
            filename = filenameprefix + ".json"
            filepath = os.path.join(self.indicators_path, filename)
            print(filepath)
            self._write_object(indicator, filepath)
            print("Indicator {} has written.".format(filenameprefix))

    def _get_indicators(self):
        indicators = []
        for stixv2file in self._get_otx_files_paths():
            with open(stixv2file, 'r') as jsonfile:
                stixv2 = json.load(jsonfile)
                jsonfile.close()
            for xobject in stixv2['objects']:
                object_type = xobject["id"].split("--")[0]
                if object_type == 'indicator':
                    indicators.append(xobject)
        return indicators

    def write_identities(self):
        for identity_tex in self._get_identities():
            identity = parse(identity_tex)
            serialized_identity = identity.serialize(pretty=True)
            filenameprefix = sha1(serialized_identity.encode()).hexdigest()
            filename = filenameprefix + ".json"
            filepath = os.path.join(self.identities_path, filename)
            print(filepath)
            self._write_object(identity, filepath)
            print("Identity {} has written.".format(filenameprefix))

    def _get_identities(self):
        identities = []
        for stixv2file in self._get_otx_files_paths():
            with open(stixv2file, 'r') as jsonfile:
                stixv2 = json.load(jsonfile)
                jsonfile.close()
            for xobject in stixv2['objects']:
                object_type = xobject["id"].split("--")[0]
                if object_type == 'identity':
                    identities.append(xobject)
        return identities

    def write_reports(self):
        for report_tex in self._get_reports():
            report = parse(report_tex)
            serialized_report = report.serialize(pretty=True)
            filenameprefix = sha1(serialized_report.encode()).hexdigest()
            filename = filenameprefix + ".json"
            filepath = os.path.join(self.reports_path, filename)
            print(filepath)
            self._write_object(report, filepath)
            print("Identity {} has written.".format(filenameprefix))

    def _get_reports(self):
        reports = []
        for stixv2file in self._get_otx_files_paths():
            with open(stixv2file, 'r') as jsonfile:
                stixv2 = json.load(jsonfile)
                jsonfile.close()
            for xobject in stixv2['objects']:
                object_type = xobject["id"].split("--")[0]
                if object_type == 'report':
                    reports.append(xobject)
        return reports

    def write_threat_actors(self):
        for threat_actor_tex in self._get_threat_actors():
            external_references_tex = threat_actor_tex['external_references'][0]
            external_references = []
            for exref in external_references_tex:
                external_references.append(ExternalReference(source_name=exref['source_name'], url=exref['url']))
            threat_actor = ThreatActor(aliases=threat_actor_tex['aliases'], created=threat_actor_tex['created'],
                                       description=threat_actor_tex['description'][0], id=threat_actor_tex['id'],
                                       labels=threat_actor_tex['labels'], name=threat_actor_tex['name'],
                                       external_references=external_references)
            serialized_threat_actor = threat_actor.serialize(pretty=True)
            filenameprefix = sha1(serialized_threat_actor.encode()).hexdigest()
            filename = filenameprefix + ".json"
            filepath = os.path.join(self.threat_actors_path, filename)
            print(filepath)
            # noinspection PyTypeChecker
            self._write_object(threat_actor, filepath)
            print("Threat Actor {} has written.".format(filenameprefix))

    def _get_threat_actors(self):
        threat_actors = []
        for stixv2file in self._get_otx_files_paths():
            with open(stixv2file, 'r') as jsonfile:
                stixv2 = json.load(jsonfile)
                jsonfile.close()
            for xobject in stixv2['objects']:
                object_type = xobject["id"].split("--")[0]
                if object_type == 'threat-actor':
                    threat_actors.append(xobject)
        return threat_actors

    def write_vulnerabilities(self):
        for vulnerability_tex in self._get_vulnerabilities():
            vulnerability = parse(vulnerability_tex)
            serialized_vulnerability = vulnerability.serialize(pretty=True)
            filenameprefix = sha1(serialized_vulnerability.encode()).hexdigest()
            filename = filenameprefix + ".json"
            filepath = os.path.join(self.vulnerabilities_path, filename)
            print(filepath)
            self._write_object(vulnerability, filepath)
            print("Vulnerability {} has written.".format(filenameprefix))

    def _get_vulnerabilities(self):
        vulnerabilities = []
        for stixv2file in self._get_otx_files_paths():
            with open(stixv2file, 'r') as jsonfile:
                stixv2 = json.load(jsonfile)
                jsonfile.close()
            for xobject in stixv2['objects']:
                object_type = xobject["id"].split("--")[0]
                if object_type == 'vulnerability':
                    vulnerabilities.append(xobject)
        return vulnerabilities

    def _create_observable(self, serialized_observable):
        observable = None
        if "url" in serialized_observable:
            observable = URL(value=serialized_observable.split("=")[1].strip().replace("'", ""))
        elif "domain" in serialized_observable:
            observable = DomainName(value=serialized_observable.split("=")[1].strip().replace("'", ""))
        elif "ipv4" in serialized_observable:
            observable = IPv4Address(value=serialized_observable.split("=")[1].strip().replace("'", ""))
        elif "file" in serialized_observable:
            if 'MD5' in serialized_observable:
                observable = File(hashes={'MD5': serialized_observable.split("=")[1].strip().replace("'", "")})
            elif 'SHA-256' in serialized_observable:
                observable = File(hashes={'SHA-256': serialized_observable.split("=")[1].strip().replace("'", "")})
            elif "SHA-1" in serialized_observable:
                observable = File(hashes={'SHA-1': serialized_observable.split("=")[1].strip().replace("'", "")})
            else:
                print("Algorithm Type not created")
        elif "email" in serialized_observable:
            emailaddress = EmailAddress(value=serialized_observable.split("=")[1].strip().replace("'", ""))
            observable = EmailMessage(from_ref=emailaddress, is_multipart=False)
        else:
            print("Observable Type not created")
            print(serialized_observable)
        return observable

    def get_observable(self):
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
            for xobject in stixv2['objects']:
                object_type = xobject["id"].split("--")[0]
                if object_type not in objects_types:
                    objects_types.append(object_type)
                    objects_per_type[object_type] = 0
                if object_type == 'indicator':
                    object_observable = xobject['pattern']
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


if __name__ == '__main__':
    STIXv2Manager().write_vulnerabilities()
