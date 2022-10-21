# Project : csc
# Developer : George Sakellariou
# Date :4/11/21
import logging
import psycopg2

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

    def insert_ctiproduct_alert(self, code, collected, link, title, text_link, source):
        sql_query = """INSERT INTO public.alerts(code, collected, link, title, text_link, source) VALUES (%s,%s,%s,%s,%s,%s) RETURNING alert_id;"""
        try:
            cur = self.connection.cursor()
            # execute the INSERT statement
            cur.execute(sql_query, (code, collected, link, title, text_link, source,))
            # get the generated id back
            id = cur.fetchone()[0]
            # commit the changes to the database
            self.connection.commit()
            # close communication with the database
            cur.close()
            self.logger.info("Alert inserted successfully : {}".format(id))
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in alert insertion :{}:{}".format(code, e))

    def insert_ctiproduct_report(self, code, collected, link, title, text_link, source):
        sql_query = """INSERT INTO public.reports(code, collected, link, title, text_link, source) VALUES (%s,%s,%s,%s,%s,%s) RETURNING report_id;"""

        try:
            cur = self.connection.cursor()
            # execute the INSERT statement
            cur.execute(sql_query, (code, collected, link, title, text_link, source,))
            # get the generated id back
            id = cur.fetchone()[0]
            # commit the changes to the database
            self.connection.commit()
            # close communication with the database
            cur.close()
            self.logger.info("Report inserted successfully :{}".format(id))
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in insertion of report:{}:{}".format(code, e))

    def insert_ctiproduct_stixv2(self, code, collected, link, title, text_link, stixv2_type, source):
        sql_query = """INSERT INTO public.reports(code, collected, link, title, text_link, stixv2_type, source) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING stixv2_id;"""

        try:
            cur = self.connection.cursor()
            # execute the INSERT statement
            cur.execute(sql_query, (code, collected, link, title, text_link, stixv2_type, source,))
            # get the generated id back
            id = cur.fetchone()[0]
            # commit the changes to the database
            self.connection.commit()
            # close communication with the database
            cur.close()
            self.logger.info("STIX v2 artifact inserted successfully :{}".format(id))
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in insertion of STIX v2 artifact:{}:{}".format(code, e))

    def get_alerts(self):
        sql_query = """SELECT code,collected,link,text_link,source FROM public.alerts"""
        try:
            cur = self.connection.cursor()
            cur.execute(sql_query)
            rows = cur.fetchall()
            cur.close()
            self.logger.info("Alerts  retrieved successfully : {}".format(len(rows)))
            return rows
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in getting alerts:{}".format(e))

    def get_reports(self):
        sql_query = """SELECT code,collected, link, text_link, source FROM public.reports;"""
        try:
            cur = self.connection.cursor()
            cur.execute(sql_query)
            rows = cur.fetchall()
            cur.close()
            self.logger.info("Reports retrieved successfully :{}".format(len(rows)))
            return rows
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in getting reports:{}".format(e))

    def update_alert(self, code, collected):
        sql_query = """UPDATE public.alerts SET collected=%s WHERE code=%s;"""
        try:
            cur = self.connection.cursor()
            # execute the UPDATE statement
            cur.execute(sql_query, (collected, code,))
            # commit the changes to the database
            self.connection.commit()
            # close communication with the database
            cur.close()
            self.logger.info("Alert updated successfully :{}".format(code))
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in updating alert:{}:{}".format(e, code))

    def update_report(self, code, collected):
        sql_query = """UPDATE public.reports SET collected=%s WHERE code=%s;"""
        try:
            cur = self.connection.cursor()
            # execute the UPDATE statement
            cur.execute(sql_query, (collected, code,))
            # commit the changes to the database
            self.connection.commit()
            # close communication with the database
            cur.close()
            self.logger.info("Report updated successfully :{}".format(code))
        except (Exception, psycopg2.DatabaseError) as e:
            self.logger.error("Error in updating report:{}:{}".format(e, code))


if __name__ == '__main__':
    dbmanager = DBManager()
    data = dbmanager.get_reports()
    print(data)
