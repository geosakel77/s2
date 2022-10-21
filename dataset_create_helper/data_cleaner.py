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


class DataCleaner:

    def __init__(self, clean_alerts_path="../datasets/text_files/alerts",
                 clean_reports_path="../datasets/text_files/reports", dirty_alerts_path="../raw_data/html_files/alerts",
                 dirty_reports_path="../raw_data/html_files/reports"):
        self.clean_alerts_path = clean_alerts_path
        self.clean_reports_path = clean_reports_path
        self.dirty_alerts_path = dirty_alerts_path
        self.dirty_reports_path = dirty_reports_path

    def get_dirty_alerts_files(self):
        dirty_alerts_files = [os.path.join(self.dirty_alerts_path, file) for file in os.listdir(self.dirty_alerts_path)]
        return dirty_alerts_files

    def get_dirty_reports_files(self):
        dirty_reports_files = [os.path.join(self.dirty_reports_path, file) for file in
                               os.listdir(self.dirty_reports_path)]
        return dirty_reports_files

    def get_clean_alerts(self):
        clean_alerts_files = [os.path.join(self.clean_alerts_path, file) for file in os.listdir(self.clean_alerts_path)]
        return clean_alerts_files


if __name__ == "__main__":
    cleaner=DataCleaner()
    print(len(cleaner.get_dirty_reports_files()))
    print(len(cleaner.get_dirty_alerts_files()))
    print(len(cleaner.get_clean_alerts()))
