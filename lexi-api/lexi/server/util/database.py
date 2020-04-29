import psycopg2
import logging
import json
import mysql.connector
from collections import defaultdict

logger = logging.getLogger('lexi')


class DatabaseConnection:

    def __init__(self, kwargs):
        self.connection = self.connect(kwargs)
        self.cursor = self.connection.cursor()
        logger.info("Connected to database '{}' at '{}'.".format(
            kwargs["name"], kwargs["host"]
        ))

    def connect(self, kwargs):
        dbtype = kwargs.get("type", "postgres")
        try:
            logger.info(dbtype)
            logger.info(dbtype == 'mysql')
            logger.info(type(dbtype))

            if dbtype == "postgres":
                args = {
                    "dbname": kwargs["name"],
                    "port": kwargs["port"],
                    "user": kwargs["user"],
                    "host": kwargs["host"],
                    "password": kwargs.get("password", "")
                }
                connection = psycopg2.connect(**args)
            elif dbtype == "mysql":
                args = {
                    "database": kwargs["name"],
                    "port": kwargs["port"],
                    "user": kwargs["user"],
                    "host": kwargs["host"],
                    "password": kwargs["password"]
                }
                connection = mysql.connector.connect(**args)
            else:
                raise NotImplementedError("Database type {} not supported. Must"
                                          "be one of "
                                          "'postgres', 'mysql'.".format(dbtype))
        except psycopg2.OperationalError:
            raise DatabaseConnectionError("Lexi could not connect.")
        except psycopg2.ProgrammingError:
            raise DatabaseConnectionError()
        return connection

    def test_connection(self):
        test_query = "SELECT * FROM users;"
        flag_worked = True
        try:
            self.execute_and_fetchone(test_query)
        except DatabaseConnectionError:
            flag_worked = False
        return flag_worked

    def execute(self, query, log=True):
        try:
            if log:
                logger.info("PSQL query: " + query)
            self.cursor.execute(query)
        except psycopg2.Error:
            self.connection.rollback()
            raise DatabaseConnectionError()

    def execute_and_fetchone(self, query, log=True):
        self.execute(query, log)
        return self.cursor.fetchone()

    def execute_and_fetchall(self, query, log=True):
        self.execute(query, log)
        return self.cursor.fetchall()

    def execute_and_commit(self, query, log=True):
        self.execute(query, log)
        self.connection.commit()

    def get_user(self, email):
        query = "SELECT user_id FROM users WHERE email='{}'".format(email)
        row = self.execute_and_fetchone(query)
        if row:
            return row[0]
        else:
            logger.warning("Did not find a user with email '{}'".format(email))

    def get_blacklist(self, user_id=None):
        if user_id:
            query = "SELECT item FROM blacklist " \
                    "WHERE user_id='{}' ;".format(user_id)
        else:
            query = "SELECT item FROM blacklist ;".format(user_id)
        items = self.execute_and_fetchall(query)
        return [item[0] for item in items]

    def add_to_blacklist(self, user_id, items):
        for item in items:
            query = "INSERT INTO blacklist " \
                    "(user_id, item) VALUES ('{}', '{}');".format(user_id, item)
            self.execute_and_commit(query)

    def get_model_path(self, user_id):
        query = "SELECT model_file FROM models WHERE user_id ={}".format(
            user_id)
        row = self.execute_and_fetchone(query)
        if row:
            return row[0]
        else:
            logger.warning("Did not find a model file for user_id {}"
                           .format(user_id))

    def get_max_user_id(self):
        query = "SELECT user_id FROM users ORDER BY user_id DESC LIMIT 1;"
        row = self.execute_and_fetchone(query)
        if row:
            return row[0]
        else:
            return 0

    def insert_user(self, email):
        new_user_id = self.get_max_user_id() + 1
        query = "INSERT INTO users " \
                "(user_id, email, first_login, last_login, num_logins) " \
                "VALUES ({}, '{}', now(), now(), {});"\
            .format(new_user_id, email, 1)
        self.execute_and_commit(query)
        return new_user_id

    def insert_model(self, new_user_id, year_of_birth, education, model,
                     model_type):
        query = "INSERT INTO models " \
                "(user_id, year_of_birth, education, model_file, model_type) " \
                "VALUES ({}, {}, '{}', '{}', '{}');"\
            .format(new_user_id, year_of_birth, education, model, model_type)
        self.execute_and_commit(query)

    def get_max_request_id(self):
        query = "SELECT request_id FROM sessions " \
                "ORDER BY request_id DESC LIMIT 1;"
        row = self.execute_and_fetchone(query)
        if row:
            return row[0]
        else:
            return 0

    def insert_session(self, user_id, website_url, simplifications=None,
                       frontend_version=None, language=None):
        request_id = self.get_max_request_id() + 1
        if not simplifications:
            simplifications = {}
        if type(simplifications) == dict:
            simplifications = json.dumps(simplifications)
        if type(simplifications) == str:
            simplifications = simplifications.replace("'", "''")
        query = "INSERT INTO sessions " \
                "(request_id, user_id, url, timestamp_start, simplifications, "\
                "frontend_version, lang_id) "\
                "VALUES ({}, {}, '{}', now(), '{}', '{}', '{}')"\
            .format(request_id, user_id, website_url, simplifications,
                    frontend_version, language)
        self.execute_and_commit(query)
        return request_id

    def update_session_with_simplifications(self, request_id, simplifications):
        if not simplifications:
            simplifications = {}
        if type(simplifications) == dict:
            simplifications = json.dumps(simplifications)
        if type(simplifications) == str:
            simplifications = simplifications.replace("'", "''")
        query = "UPDATE sessions SET " \
                "simplifications = '{}' " \
                "WHERE request_id = {}; "\
            .format(simplifications, request_id)
        self.execute_and_commit(query)

    def update_session_with_feedback(self, rating, feedback_text,
                                     simplifications):
        if not simplifications:
            simplifications = {}
        if type(simplifications) == str:
            simplifications = simplifications.replace(
                "'", "''")
        # aggregate by request ID
        request2simplifications = defaultdict(list)
        for target, target_simplfication in simplifications.items():
            request_id = target_simplfication['request_id']
            request2simplifications[request_id].append(target_simplfication)

        for request_id, request_simplifications in request2simplifications.items():
            request_simplifications = json.dumps(request_simplifications)
            if type(request_simplifications) == str:
                request_simplifications = request_simplifications.replace(
                    "'", "''")

            query = "UPDATE sessions SET " \
                    "timestamp_feedback = now(), " \
                    "feedback_text = '{}', " \
                    "simplifications = '{}', " \
                    "rating = {} " \
                    "WHERE request_id = {}; " \
                .format(feedback_text, request_simplifications,
                        rating, request_id)
            self.execute_and_commit(query)


class DatabaseConnectionError(Exception):

    def __init__(self, message=None):
        if message:
            self.message = message
