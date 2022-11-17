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
    exp4 = _load('experiment_4_results.json')
    return exp1, exp2, exp3, exp4


def exp1_plot(exp):
    x_axis_labels = list(exp.keys())
    width = 0.15
    x_axis_1 = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
    x_axis_2 = [x + width for x in x_axis_1]
    x_axis_3 = [x + width for x in x_axis_2]
    x_axis_4 = [x + width for x in x_axis_3]
    x_axis_5 = [x + width for x in x_axis_4]
    x_axis_6 = [x + width for x in x_axis_5]
    x_axis_7 = [x + width for x in x_axis_6]
    x_axis_8 = [x + width for x in x_axis_7]
    x_axis_9 = [x + width for x in x_axis_8]
    x_axis_10 = [x + width for x in x_axis_9]
    x_axis_11 = [x + width for x in x_axis_10]
    bunlde = []
    identity = []
    indicator = []
    ipv4_addr = []
    domain_name = []
    email_message = []
    url = []
    file = []
    report = []
    threat_actor = []
    vulnerability = []
    for org in exp.keys():
        bunlde.append(exp[org]['bundle'])
        identity.append(exp[org]['identity'])
        indicator.append(exp[org]['indicator'])
        ipv4_addr.append(exp[org]['ipv4-addr'])
        domain_name.append(exp[org]['domain-name'])
        email_message.append(exp[org]['email-message'])
        url.append(exp[org]['url'])
        file.append(exp[org]['file'])
        report.append(exp[org]['report'])
        threat_actor.append(exp[org]['threat-actor'])
        vulnerability.append(exp[org]['vulnerability'])

    plt.bar(np.array(x_axis_1), np.array(bunlde), width=width, label='Bundle')
    plt.bar(np.array(x_axis_2), np.array(identity), width=width, label='Identity')
    plt.bar(np.array(x_axis_3), np.array(indicator), width=width, label='Indicator')
    plt.bar(np.array(x_axis_4), np.array(ipv4_addr), width=width, label='IPv4-Addr')
    plt.bar(np.array(x_axis_5), np.array(domain_name), width=width, label='Domain-Name')
    plt.bar(np.array(x_axis_6), np.array(email_message), width=width, label='Email Message')
    plt.bar(np.array(x_axis_7), np.array(url), width=width, label='URL')
    plt.bar(np.array(x_axis_8), np.array(file), width=width, label='File')
    plt.bar(np.array(x_axis_9), np.array(report), width=width, label='Report')
    plt.bar(np.array(x_axis_10), np.array(threat_actor), width=width, label='Threat Actor')
    plt.bar(np.array(x_axis_11), np.array(vulnerability), width=width, label='Vulnerability')
    plt.ylabel('Weighted Completeness')
    plt.xlabel('Organization')
    plt.xticks(np.array(x_axis_6), x_axis_labels)
    plt.legend()
    plt.title("(a)")
    plt.show()


def exp2_plot(exp):
    x_axis_labels = list(exp.keys())
    width = 0.15
    x_axis_1 = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
    x_axis_2 = [x + width for x in x_axis_1]
    x_axis_3 = [x + width for x in x_axis_2]
    x_axis_4 = [x + width for x in x_axis_3]
    x_axis_5 = [x + width for x in x_axis_4]
    x_axis_6 = [x + width for x in x_axis_5]
    doc1 = []
    doc2 = []
    doc3 = []
    doc4 = []
    doc5 = []
    doc6 = []

    for org in exp.keys():
        doc1.append(exp[org]['doc1'])
        doc2.append(exp[org]['doc2'])
        doc3.append(exp[org]['doc3'])
        doc4.append(exp[org]['doc4'])
        doc5.append(exp[org]['doc5'])
        doc6.append(exp[org]['doc6'])

    plt.bar(np.array(x_axis_1), np.array(doc1), width=width, label='Doc1')
    plt.bar(np.array(x_axis_2), np.array(doc2), width=width, label='Doc2')
    plt.bar(np.array(x_axis_3), np.array(doc3), width=width, label='Doc3')
    plt.bar(np.array(x_axis_4), np.array(doc4), width=width, label='Doc4')
    plt.bar(np.array(x_axis_5), np.array(doc5), width=width, label='Doc5')
    plt.bar(np.array(x_axis_6), np.array(doc6), width=width, label='Doc6')
    plt.ylabel('Weighted Completeness')
    plt.xlabel('Organization')
    plt.xticks(np.array(x_axis_3), x_axis_labels)
    plt.legend()
    plt.title("(b)")
    plt.show()


def exp3_plot(exp):
    x_axis_labels = list(exp.keys())
    x_axis = list(range(1, 11))
    y_time = []
    y_cpu_time = []
    for org in exp.keys():
        y_time.append(exp[org]['doc1']['time'] * 1000)
        y_cpu_time.append(exp[org]['doc1']['cpu_time'] * 1000)

    plt.scatter(np.array(x_axis), np.array(y_time), s=6, label='Execution Time')
    plt.scatter(np.array(x_axis), np.array(y_cpu_time), s=6, label='CPU Execution Time')
    plt.ylabel('milliseconds')
    plt.xlabel('Organization')
    plt.xticks(np.array(x_axis), x_axis_labels)
    plt.legend()
    plt.title("(c)")
    plt.show()


def exp4_plot(exp, exp1):
    x_axis_labels = list(exp.keys())
    width = 0.15
    x_axis = list(range(1, 11))
    doc1 = []
    for org in exp.keys():
        doc1.append(exp[org]['doc1'])
    doc11 = []
    for org in exp1.keys():
        doc11.append(exp1[org]['doc1'])
    plt.scatter(np.array(x_axis), np.array(doc1), label='Weighted Completeness')
    plt.scatter(np.array(x_axis), np.array(doc11), label='Completeness')
    plt.ylabel('Metric Value of Document 1')
    plt.xlabel('Organization')
    plt.xticks(np.array(x_axis), x_axis_labels)
    plt.legend()
    plt.title("(d)")
    plt.show()


def plot_main():
    exp1, exp2, exp3, exp4 = load_data()
    # exp1_plot(exp1)
    # exp2_plot(exp2)
    # exp3_plot(exp3)
    exp4_plot(exp2, exp4)


if __name__ == "__main__":
    plot_main()
