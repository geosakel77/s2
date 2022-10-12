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
import csv
import json


def read_dit_csv(filename, delimiter=','):
    with open(filename, 'r') as f:
        csvreader = csv.reader(f, delimiter=delimiter)
        next(csvreader)
        delta_dictionary = {}
        for row in csvreader:
            if row[4].strip() not in delta_dictionary.keys():
                delta_dictionary[row[4].strip()] = [row[3]]
            else:
                delta_dictionary[row[4].strip()].append(row[3])
        return delta_dictionary


def tranform_delta(delta_dictionary):
    tranformed_delta = {}
    delta = delta_dictionary.keys()
    for delta_l in delta:
        delta_l_words = []
        for phrase in delta_dictionary[delta_l]:
            for word in phrase.replace(',', " ").split():
                if word.strip() not in delta_l_words:
                    delta_l_words.append(word.strip().lower())
        tranformed_delta[delta_l] = delta_l_words
    return tranformed_delta


def store_delta(transformed_delta):
    with open("../datasets/delta.json", 'w') as out:
        json.dump(transformed_delta, out)
        out.close()


if __name__ == '__main__':
    data = read_dit_csv("../raw_data/data_dit_full.csv", delimiter=';')
    store_delta(tranform_delta(data))
