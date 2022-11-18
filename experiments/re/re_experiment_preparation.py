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

import nltk
from nltk.corpus import PlaintextCorpusReader
from nltk.probability import FreqDist
from nltk.stem import LancasterStemmer


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
    delta_keys_list = list(delta.keys())
    for i in range(0, rank):
        seed = random.randint(0, 25)
        delta_list.append({delta_keys_list[seed]: delta[delta_keys_list[seed]]})
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


def _transform_cpe_entry(cpe):
    words = []
    for key in cpe:
        if len(cpe[key]) > 0:
            words.append(cpe[key].split('_'))
    flatten_words = list(itertools.chain(*words))
    return flatten_words


def _remove_stopwords(words_list):
    stopwords = nltk.corpus.stopwords.words('english')
    words_ne = []
    for word in words_list:
        if word not in stopwords:
            words_ne.append(word)
    return words_ne


def _tranform_giota(giota):
    words_bunch = []
    for cpe in giota:
        words = _transform_cpe_entry(cpe)
        words_bunch.append(words)
    flatten_words_bunch = list(itertools.chain(*words_bunch))
    ne_flatten_words_bunch = _remove_stopwords(flatten_words_bunch)
    nlp_words = nltk.FreqDist(ne_flatten_words_bunch)
    return nlp_words


def transform_all_organizations_giota(all_giota):
    all_organizations_transformed_giota = {}
    for organization in all_giota.keys():
        transformed_organization_giota = _tranform_giota(all_giota[organization])
        all_organizations_transformed_giota[organization] = transformed_organization_giota
    return all_organizations_transformed_giota


def _lemmatizer(doc_keys, stemmer):
    stemmed_keys = {}
    for dockey in doc_keys.keys():
        stemmed_keys[dockey] = stemmer.stem(doc_keys[dockey])
    return stemmed_keys


def _lemmatizer_1(wordlists, stemmer):
    stemmed_words = []
    for word in wordlists:
        stemmed_words.append(stemmer.stem(word))
    return stemmed_words


def create_delta_p1(doc1, giota):
    stemmer = LancasterStemmer()
    delta_p1 = {}
    tempdockeys = {}
    for dockey in doc1.keys():
        tempdockeys[dockey] = dockey
    dockeys = _lemmatizer(tempdockeys, stemmer)
    print("Pu length words:{}".format(len(list(doc1.keys()))))
    for key1 in dockeys.keys():
        value = dockeys[key1]
        for word in list(giota.keys()):
            if value in word.lower():
                delta_p1[word] = doc1[key1]
    print("Delta length:{}".format(len(list(delta_p1.keys()))))
    print("Giota length:{}".format(len(list(giota.keys()))))
    return delta_p1


def create_all_delta_p1(documents, giota):
    all_delta_p1 = []
    for dataset in documents:
        for doc_type in dataset.keys():
            organizations_corpus = PlaintextCorpusReader(os.path.join('../../datasets/text_files', doc_type), '.*')
            for document in dataset[doc_type]:
                print("Create delta p1 for:{}".format(document))
                wordslist = organizations_corpus.words(document)
                clean_wordlist = _remove_stopwords(wordslist)
                filtered_wordlist = [word for word in clean_wordlist if len(word) > 3]
                delta_p1 = create_delta_p1(FreqDist(filtered_wordlist), giota)
                all_delta_p1.append((delta_p1, document))
    return all_delta_p1


def create_all_organizations_delta_p1(all_pu):
    giota_raw = _load('all_organizations_giota_transformed.json')
    all_organizations_delta_p1 = {}
    for organization in all_pu.keys():
        print("Create deltas for:{}".format(organization))
        giota = FreqDist(giota_raw[organization])
        all_organizations_delta_p1[organization] = create_all_delta_p1(all_pu[organization], giota)
    return all_organizations_delta_p1


def create_tranformed_delta(delta):
    transformed_delta = {}
    for organization in delta.keys():
        all_organization_domains_data = []
        delta_data = delta[organization]
        for industry_domains in delta_data:
            organization_domains_data = []
            for industry_domain in industry_domains.keys():
                dn = [word.replace(',', '') for word in industry_domain.split(' ')]
                organization_domains_data.append(industry_domains[industry_domain])
                organization_domains_data.append(dn)
            all_organization_domains_data.append(organization_domains_data)
        a = list(itertools.chain(*all_organization_domains_data))
        data_flatten = list(itertools.chain(*a))
        data_cleaned = _remove_stopwords(list(set(data_flatten)))
        transformed_delta[organization] = data_cleaned
    return transformed_delta


def create_delta_p2(wordlist, delta):
    stemmer = LancasterStemmer()
    delta_p2 = []
    lemma_words = list(set(_lemmatizer_1(wordlist, stemmer)))
    print("Pu length words:{}".format(len(lemma_words)))
    for lemma in lemma_words:
        for word in delta:
            if lemma in word.lower():
                delta_p2.append(lemma)
    return delta_p2


def create_all_delta_p2(documents, delta):
    all_delta_p2 = []
    for dataset in documents:
        for doc_type in dataset.keys():
            organizations_corpus = PlaintextCorpusReader(os.path.join('../../datasets/text_files', doc_type), '.*')
            for document in dataset[doc_type]:
                print("Create delta p2 for:{}".format(document))
                wordslist = organizations_corpus.words(document)
                clean_wordlist = _remove_stopwords(wordslist)
                filtered_wordlist = [word for word in clean_wordlist if len(word) > 3]
                delta_p2 = create_delta_p2(filtered_wordlist, delta)
                all_delta_p2.append((delta_p2, document))
    return all_delta_p2


def create_all_organizations_delta_p2(all_pu):
    deltas = _load('all_organizations_delta_transformed.json')
    all_organization_deltas_p2 = {}
    for organization in all_pu.keys():
        print("Create deltas p2 for:{}".format(organization))
        delta = deltas[organization]
        all_organization_deltas_p2[organization] = create_all_delta_p2(all_pu[organization], delta)
    return all_organization_deltas_p2


if __name__ == "__main__":
    all_delta, all_giota, all_pu = load_data()
    # write_json(transform_all_organizations_giota(all_giota),'all_organizations_giota_transformed.json')
    # write_json(create_all_organizations_giota(), 'all_organizations_giota.json')
    # write_json(create_all_organizations_delta(),'all_organizations_delta.json')
    # write_json(create_all_organizations_delta_p1(all_pu),'all_organizations_delta_p1.json')
    # write_json(create_tranformed_delta(delta=all_delta),'all_organizations_delta_transformed.json')
    write_json(create_all_organizations_delta_p2(all_pu), 'all_organizations_delta_p2.json')
