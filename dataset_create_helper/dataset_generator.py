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
import feedparser
from bs4 import BeautifulSoup

SOURCES={"https://us-cert.cisa.gov/ics/alerts/alerts.xml"}

class RSSSourcesHandler:
    def __init__(self):
        self.sources = SOURCES
        self.rssfeedhandlers = self._get_feeds()

    def _get_feeds(self):
        try:
            rssfeedhandlers = {}
            for source in self.sources:
                rssfeedhandlers[source[0]] = RSSFeedsHandler(source[1])
            return rssfeedhandlers
        except IOError as e:
            print(e)

    @staticmethod
    def _clean_title(dirty_title):
        try:
            soup = BeautifulSoup(dirty_title, "html.parser")
            title = soup.find('a')
            return title.string
        except:
            title = dirty_title
            return title


class RSSFeedsHandler:

    def __init__(self, feed):
        self.feed = feed
        self.newsfeed = None
        self._retrieve_feeds()
        self.entries = None
        self._get_entries()

    def _retrieve_feeds(self):
        self.newsfeed = feedparser.parse(self.feed)

    def _get_entries(self):
        self.entries = self.newsfeed.entries

    def _get_summary_detail(self, entry):
        return entry.summary_detail

    def _get_entry_id(self, entry):
        return entry.id

    def _get_entry_published_parsed(self, entry):
        return entry.published_parsed

    def _get_entry_links(self, entry):
        return entry.links

    def _get_entry_title(self, entry):
        return entry.title

    def _get_entry_summary(self, entry):
        return entry.summary

    def _get_entry_guidislink(self, entry):
        return entry.guidislink

    def _get_entry_title_detail(self, entry):
        return entry.title_detail

    def _get_entry_link(self, entry):
        return entry.link

    def _get_entry_published(self, entry):
        return entry.published

    def print_entry(self, entry):
        data = "--------------------------------------------Entry Report--------------------------------------------\n" \
               "Entry ID: {}\n" \
               "Title: {}\n" \
               "Entry Link: {}\n" \
               "Entry Published: {}\n" \
               "Entry Published Parsed: {}\n" \
               "Entry gUIDisLink: {}\n" \
               "Entry Links: {}\n" \
               "**************************** Entry Title Detail****************************\n" \
               "{}\n" \
               "**************************** Entry Title Detail ****************************\n" \
               "**************************** Summary ****************************\n" \
               "{}\n" \
               "**************************** Summary ****************************\n" \
               "**************************** Detailed Summary ****************************\n" \
               "{}\n" \
               "**************************** Detailed Summary ****************************\n" \
               "--------------------------------------------Entry Report--------------------------------------------".format(
            self._get_entry_id(entry),
            self._get_entry_title(entry), self._get_entry_link(entry), self._get_entry_published(entry),
            self._get_entry_published_parsed(entry), self._get_entry_guidislink(entry),
            self._get_entry_links(entry), self._get_entry_title_detail(entry),
            self._get_entry_summary(entry), self._get_summary_detail(entry))
        print(data)

if __name__ == '__main__':
    print("s2")


