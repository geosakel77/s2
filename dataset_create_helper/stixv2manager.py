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
import os

class STIXv2Manager:
    def __init__(self,otx_path="../datasets/stixv2/otx",xforce_path="../datasets/stixv2/xforce"):
        self.otx_path =otx_path
        self.xforce_path = xforce_path

    def get_otx_files(self):
        otx_files = [os.path.join(self.otx_path, file) for file in os.listdir(self.otx_path)]
        return otx_files




if __name__ == '__main__':
    STIXv2Manager.get_otx_files()
