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


def wc_metric(weights, delta_p, delta_s):
    sum_1 = 0
    sum_2 = 0
    for i in range(len(delta_s)):
        sum_1 += weights[i] * (delta_p[i] / delta_s[i])
        if weights[i] > 0:
            sum_2 += 1
    if sum_2 != 0:
        f = sum_1 / sum_2
    else:
        f = None
    return f


def c_metric(delta_p, delta_s):
    sum_1 = 0
    sum_2 = 0
    for i in range(len(delta_s)):
        sum_1 += delta_s[i] - delta_p[i]
        sum_2 += delta_s[i]
        f = sum_1 / sum_2
    return f
