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

from math import sqrt


def re_metric(delta_i, delta_p1, delta_d, delta_p2):
    a = 0
    b = 0
    sum_2 = 0
    for k in delta_i:
        a += k ^ 2
    for k in delta_p1:
        b += k ^ 2
    sum_1 = sqrt(a) * sqrt(b)
    for i in range(len(delta_p1)):
        sum_2 += delta_i[i] * delta_p1[i]
    f1 = sum_1 / sum_2
    f2 = len(delta_p2) / len(delta_d)
    if (f1 == 0) and (f2 != 0):
        f = f2
    elif (f1 != 0) and (f2 == 0):
        f = f1
    else:
        f = f1 * f2
    return f
