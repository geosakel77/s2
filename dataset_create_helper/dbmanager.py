# Project : csc
# Developer : George Sakellariou
# Date :4/11/21
import psycopg2,json,logging
from config import config




class DBManager:
    def __init__(self):
        logging.basicConfig(format='%(asctime)s :: %(levelname)s :: %(funcName)s :: %(lineno)d :: %(message)s',
                            level=logging.INFO, filename='log/dbmanager.log')
        self.logger = logging.getLogger('DatabaseManager')
        self.connection = self._connect()

    def _connect(self):
        """ Connect to the PostgreSQL database server """
        conn = None
        try:
            # read connection parameters
            params = config()
            # connect to the PostgreSQL server
            conn = psycopg2.connect(**params)
            self.logger.info("Client connected to database : {}".format(conn))
            return conn
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in database connection :{}".format(e))

    def insert_source(self, source, description):
        sql_query="""INSERT INTO public.feedsources(address, description) VALUES (%s, %s) RETURNING id;"""
        try:
            cur = self.connection.cursor()
            # execute the INSERT statement
            cur.execute(sql_query, (source,description,))
            # get the generated id back
            id = cur.fetchone()[0]
            # commit the changes to the database
            self.connection.commit()
            # close communication with the database
            cur.close()
            self.logger.info("Source inserted successfully : {}".format(id))
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in source insertion :{}".format(e))

    def get_source_id(self,source):
        sql_query="""SELECT id FROM public.feedsources where address=%s"""

        try:
            cur = self.connection.cursor()
            cur.execute(sql_query, (source,))
            row = cur.fetchone()
            while row is not None:
                row = cur.fetchone()
            cur.close()
            self.logger.info("Source id retrieved successfully : {}".format(row))
            return row
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in getting source id :{}:{}".format(source,e))

    def get_source_address(self, source_id):
        sql_query = """SELECT address FROM public.feedsources where id=%s"""
        try:
            cur = self.connection.cursor()
            cur.execute(sql_query, (source_id,))
            row = cur.fetchone()
            cur.close()
            self.logger.info("Source address retrieved successfully : {}".format(row))
            return row
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in getting address of id :{}:{}".format(source_id,e))

    def get_sources(self):
        sql_query = """SELECT id,address FROM public.feedsources"""
        try:
            cur = self.connection.cursor()
            cur.execute(sql_query)
            rows = cur.fetchall()
            cur.close()
            self.logger.info("Sources  retrieved successfully : {}".format(rows))
            return rows
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in getting sources:{}".format(e))


    def insert_rss_feed(self,rss_feed_id, published, title, links,  summary, source_id):
        sql_query = """INSERT INTO public.rssfeeds(rss_feed_id, published, title, links, summary, source_id)
         VALUES (%s, %s, %s, %s, %s, %s) RETURNING rss_feed_dbid;"""
        try:
            cur = self.connection.cursor()
            # execute the INSERT statement

            cur.execute(sql_query, (rss_feed_id, published, title, json.dumps({1:links}), summary, source_id,))
            # get the generated id back
            id = cur.fetchone()[0]
            # commit the changes to the database
            self.connection.commit()
            # close communication with the database
            cur.close()
            self.logger.info("Feed inserted successfully :{}".format(id))
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in insertion of feed:{}:{}".format(rss_feed_id,e))


    def get_feed(self,rss_feed_id):
        sql_query = """SELECT rss_feed_dbid, rss_feed_id, title, summary, source_id, links, published 
        FROM public.rssfeeds WHERE rss_feed_id=%s;"""
        try:
            cur = self.connection.cursor()
            cur.execute(sql_query,(rss_feed_id,))
            rows = cur.fetchall()
            cur.close()
            self.logger.info("Feed retrieved successfully : {}".format(rows))
            return rows
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in getting feed:{}:{}".format(rss_feed_id,e))

    def get_feeds(self):
        sql_query = """SELECT rss_feed_dbid,rss_feed_id, title, summary, source_id, links, published 
           FROM public.rssfeeds;"""
        try:
            cur = self.connection.cursor()
            cur.execute(sql_query)
            rows = cur.fetchall()
            cur.close()
            self.logger.info("Feeds retrieved successfully :{}".format(rows))
            return rows
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in getting feeds:{}".format(e))

    def update_posted_list(self, feed_db_id, posted):
        sql_query = """INSERT INTO public.posted(feed_db_id,posted) VALUES (%s, %s) RETURNING post_id;"""
        try:
            cur = self.connection.cursor()
            # execute the INSERT statement

            cur.execute(sql_query, (feed_db_id, posted,))
            # get the generated id back
            post_id = cur.fetchone()[0]
            # commit the changes to the database
            self.connection.commit()
            # close communication with the database
            cur.close()
            self.logger.info("Posted list updated successfully :{}".format(post_id))
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in updating posted list:{}".format(e))

    def check_posted(self,feed_db_id):
        sql_query = """SELECT post_id, posted FROM public.posted WHERE feed_db_id=%s;"""
        try:
            cur = self.connection.cursor()
            cur.execute(sql_query,(feed_db_id,))
            rows = cur.fetchall()
            cur.close()
            self.logger.info("Posted list checked for: {}".format(feed_db_id))
            if len(rows)>0:
                return True
            else:
                return False
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in checking posted list:{}".format(e))


if __name__ == '__main__':
    import datetime, json
    dbmanager = DBManager()
    dbmanager.get_feeds()
