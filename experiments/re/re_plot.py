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

import matplotlib.pyplot as plt
import numpy as np


def _load(path):
    with open(path, 'r', encoding='utf-8') as jsonfile:
        data = json.load(jsonfile)
        jsonfile.close()
    return data


def load_data():
    exp1 = _load('experiment_1_results.json')
    exp2 = _load('experiment_2_results.json')
    exp3 = _load('experiment_3_results.json')
    return exp1, exp2, exp3


def exp1_plot(exp):
    print(exp)
    x_axis_labels = list(exp.keys())
    width = 0.30
    x_axis = list(range(1, 11))
    avg_values = []
    for org in exp.keys():
        avg_values.append(exp[org])
    plt.bar(np.array(x_axis), np.array(avg_values), width=width)
    plt.ylabel('Average Value of Relevance Metric in Pui')
    plt.xlabel('Organization')
    plt.xticks(np.array(x_axis), x_axis_labels)
    plt.legend()
    plt.title("(a)")
    plt.show()


def exp2_plot(exp):
    x_axis_labels = list(exp.keys())
    x_axis = list(range(1, 11))
    doc1 = []
    doc2 = []
    for org in exp.keys():
        dockey = list(exp[org].keys())
        doc1.append(exp[org][dockey[0]])
        doc2.append(exp[org][dockey[1]])
    plt.scatter(np.array(x_axis), np.array(doc1), label='Unstructured CTI Product 1')
    plt.scatter(np.array(x_axis), np.array(doc2), label='Unstructured CTI Product 2')
    plt.ylabel('Relevance')
    plt.xlabel('Organization')
    plt.xticks(np.array(x_axis), x_axis_labels)
    plt.legend()
    plt.title("(b)")
    plt.show()


def exp3_plot(exp):
    x_axis_labels = list(exp.keys())
    x_axis = list(range(1, 11))
    y_time = []
    i = 1
    for org in exp.keys():
        y_time.append(exp[org]["artificial_item_" + str(i)]['time'] * 1000)
        i += 1
    plt.scatter(np.array(x_axis), np.array(y_time), s=6, label='Execution Time')
    plt.ylabel('milliseconds')
    plt.xlabel('Organization')
    plt.xticks(np.array(x_axis), x_axis_labels)
    plt.legend()
    plt.title("(c)")
    plt.show()


def plot_main():
    exp1, exp2, exp3 = load_data()
    # exp1_plot(exp1)
    # exp2_plot(exp2)
    exp3_plot(exp3)


if __name__ == "__main__":
    plot_main()
