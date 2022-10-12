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
import time

import feedparser,requests
from bs4 import BeautifulSoup

SOURCES = {"https://us-cert.cisa.gov/ics/alerts/alerts.xml"}

class RSSEntryHandler:

    def __init__(self, entry):
        self.entry = entry

    def get_title(self):
        return self.entry.title

    def get_published(self):
        return self.entry.published

    def get_summary(self):
        return self.entry.summary

    def get_summary_detail(self):
        return self.entry.summary_detail

    def get_id(self):
        return self.entry.id

    def get_published_parsed(self):
        return self.entry.published_parsed

    def get_links(self):
        return self.entry.links

    def get_guidislink(self):
        return self.entry.guidislink

    def get_title_detail(self):
        return self.entry.title_detail

    def get_link(self):
        return self.entry.link

class RSSFeedsHandler:

    def __init__(self, feed):
        self.feed = feed
        self.newsfeed = None
        self._retrieve_feeds()
        self.entries = []
        self._get_entries()

    def _retrieve_feeds(self):
        self.newsfeed = feedparser.parse(self.feed)

    def _get_entries(self):
        entries=self.newsfeed.entries
        for entry in entries:
            self.entries.append(RSSEntryHandler(entry))

class RSSSourcesHandler:
    def __init__(self):
        self.sources = SOURCES
        self.rssfeedhandlers = self._get_rssfeedshandlers()

    def _get_rssfeedshandlers(self):
        try:
            rssfeedhandlers = {}
            for source in self.sources:
                rssfeedhandlers[source] = RSSFeedsHandler(source)
            return rssfeedhandlers
        except IOError as e:
            print(e)

    def print_all(self):
        for key in self.rssfeedhandlers.keys():
            self._print_feeds(self.rssfeedhandlers[key])

    def _print_feeds(self,rssfeedhandler):
        count = 0
        for entry in rssfeedhandler.entries:
            self._print_entry(entry)
            count += 1
            print(count)

    def _print_entry(self, entry):
        data = "{}\n" \
               "{}\n" \
               "{}\n".format(entry.get_title(), entry.get_published(), entry.get_summary())
        print(data)

    @staticmethod
    def _clean_title(dirty_title):
        try:
            soup = BeautifulSoup(dirty_title, "html.parser")
            title = soup.find('a')
            return title.string
        except:
            title = dirty_title
            return title

class RSSEntryContent:

    def __init__(self,url):
        self.url=url
        self.headers = {'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET','Access-Control-Allow-Headers': 'Content-Type','Access-Control-Max-Age': '3600',
                        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'}
        self.raw_content=None
        self._get_content()


    def _get_content(self):
        req=requests.get(self.url,headers=self.headers)
        self.raw_content=BeautifulSoup(req.content,'html.parser')


class StoreFeedsContent:

    def __init__(self,resourcehandler):
        self.resourcehandler=resourcehandler
        self.timestamp = time.asctime()
        self.data={}

    def _get_contents(self):
        count=0
        for key in rsssourcehandler.rssfeedhandlers.keys():
            for entry in rsssourcehandler.rssfeedhandlers[key].entries:
                count+=1
                self.data[count]=RSSEntryContent(entry.get_link()).raw_content.prettify()

    def write_data(self):
        with open("../datasets/"+self.timestamp+".json",'w') as jsonfile:
            json.dump(self.data,jsonfile)
            jsonfile.close()


if __name__ == '__main__':
    rsssourcehandler = RSSSourcesHandler()
    for key in rsssourcehandler.rssfeedhandlers.keys():
        for entry in rsssourcehandler.rssfeedhandlers[key].entries:
            print(RSSEntryContent(entry.get_link()).raw_content.prettify())
            print("-----------------------------------------------------------------------\n")



