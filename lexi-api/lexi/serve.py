import argparse
import copy
import getpass
import logging
import os
import traceback
import uuid
from configparser import ConfigParser
from logging.handlers import TimedRotatingFileHandler
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sslify import SSLify
from lexi.server.util.database import DatabaseConnection, \
    DatabaseConnectionError
from werkzeug.exceptions import HTTPException

from lexi.config import LEXI_BASE, LOG_DIR, RANKER_PATH_TEMPLATE, \
    CWI_PATH_TEMPLATE, MODELS_DIR, RESOURCES, SCORER_PATH_TEMPLATE,\
    SCORER_MODEL_PATH_TEMPLATE, SIMPLE_SCORER_PATH_TEMPLATE, BLACKLIST_PATH
from lexi.core.endpoints import update_ranker, process_text_lexical
from lexi.core.simplification.lexical import LexicalSimplificationPipeline, \
    LexiCWI, LexiRanker, LexiGenerator, LexiScorer, SimpleLexiScorer
from lexi.core.util.util import read_blacklist_words
from lexi.server.util import statuscodes
from lexi.server.util.html import process_html
from lexi.server.util.communication import make_response

SCRIPTDIR = os.path.dirname(os.path.realpath(__file__))

# os.makedirs(MODELS_DIR, exist_ok=True)

# LOGGING
# os.makedirs(LOG_DIR, exist_ok=True)
logger = logging.getLogger('lexi')
log_level = logging.DEBUG
# get logging level from CL argument, if set
logger.setLevel(log_level)
fh = TimedRotatingFileHandler(LOG_DIR+'/lexi.log', when="midnight",
                              interval=1, encoding="UTF-8")
fh.suffix = "%Y-%m-%d"
fh.setLevel(log_level)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(log_level)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - '
                              '{%(filename)s:%(lineno)d} '
                              '%(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)


# CONFIGS
cfg = ConfigParser()
fs = cfg.read(LEXI_BASE+"/lexi.cfg")


# FLASK SETUP
app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.debug = False


# LOADING DEFAULT MODEL
simplification_pipeline = LexicalSimplificationPipeline("default")
generator = LexiGenerator(synonyms_files=RESOURCES["da"]["synonyms"],
                          embedding_files=RESOURCES["da"]["embeddings"])
simplification_pipeline.setGenerator(generator)

# default_scorer = LexiScorer.staticload(SCORER_PATH_TEMPLATE.format("default"))
default_scorer = SimpleLexiScorer.staticload(
    SIMPLE_SCORER_PATH_TEMPLATE.format("default"))
print(default_scorer)
logger.debug("SCORER PATH: {}".format(default_scorer.path))
default_ranker = LexiRanker.staticload(RANKER_PATH_TEMPLATE.format("default"))
default_ranker.set_scorer(default_scorer)
default_cwi = LexiCWI.staticload(CWI_PATH_TEMPLATE.format("default"))
default_cwi.set_scorer(default_scorer)

personalized_rankers = {"default": default_ranker}
personalized_cwi = {"default": default_cwi}
personalized_scorers = {"default": default_scorer}

logger.debug("Default ranker: {} ({})".format(default_ranker,
                                              type(default_ranker)))
logger.info("Base simplifier loaded.")

# BLACKLISTED WORDS, not to be simplified
GENERIC_BLACKLIST = read_blacklist_words(BLACKLIST_PATH)
logger.debug("Generic blacklist: {}".format(GENERIC_BLACKLIST))


@app.errorhandler(Exception)
def handle_error(e):
    code = statuscodes.UNKNOWN_ERROR
    if isinstance(e, HTTPException):
        code = e.code
    logger.error(e)
    logger.error(traceback.format_exc())
    return jsonify(error=str(e)), code


@app.route("/api/simplify", methods=["POST"])
def process():
    email = request.json["email"].lower()
    website_url = request.json["url"]
    language = request.json.get("languageId")
    frontend_version = request.json.get("frontend_version", "N/A")
    logger.info("Received simplification request from user {} for website {}"
                .format(email, website_url))
    logger.debug("Simplification request: {}".format(request.json))
    user_id = 1
    if not user_id or user_id is None:
        user_id = 1  # default user. TODO issue warning here to user
    logger.info("User ID: {}".format(user_id))
    request_id = str(uuid.uuid1())
    cwi = None
    single_word_request = request.json.get("single_word_request", False)
    if not single_word_request:
        cwi = get_personalized_cwi(user_id)

    ranker = get_personalized_ranker(user_id)

    logger.info("Loaded CWI: "+str(cwi))
    logger.info("Loaded ranker: "+str(ranker))
    min_similarity = request.json.get("min_similarity", 0.65)
    if not type(min_similarity) == float:
        raise ValueError("'min_similarity' must be a float. You "
                         "provided a {}".format(type(min_similarity)))
    html_out, simplifications = process_html(simplification_pipeline,
                                             request.json["html"],
                                             request.json.get("startOffset"),
                                             request.json.get("endOffset"),
                                             cwi, ranker, mode="lexical",
                                             requestId=request_id,
                                             min_similarity=min_similarity,
                                             blacklist=GENERIC_BLACKLIST)
    # db_connection.update_session_with_simplifications(request_id,
    #                                                   simplifications)
    return make_response(statuscodes.OK,
                         "Simplification successful",
                         html=html_out,
                         simplifications=simplifications,
                         request_id=request_id)



@app.route("/api/simplify_txt", methods=["POST"])
def process_txt():
    email = request.json["email"].lower()
    website_url = request.json["url"]
    language = request.json.get("languageId")
    frontend_version = request.json.get("frontend_version", "N/A")
    logger.info("Received simplification request from user {} for website {}"
                .format(email, website_url))
    logger.debug("Simplification request: {}".format(request.json))
    user_id = 1
    if not user_id or user_id is None:
        user_id = 1  # default user. TODO issue warning here to user
    logger.info("User ID: {}".format(user_id))
    request_id = str(uuid.uuid1()) 
    # db_connection.insert_session(user_id, website_url,
    #                                           frontend_version=frontend_version,
    #                                           language=language)

    cwi = None
    single_word_request = request.json.get("single_word_request", False)
    if not single_word_request:
        cwi = get_personalized_cwi(user_id)

    ranker = get_personalized_ranker(user_id)

    logger.info("Loaded CWI: "+str(cwi))
    logger.info("Loaded ranker: "+str(ranker))
    min_similarity = request.json.get("min_similarity", 0.65)
    if not type(min_similarity) == float:
        raise ValueError("'min_similarity' must be a float. You "
                         "provided a {}".format(type(min_similarity)))
    simplifications = process_text_lexical(simplification_pipeline,
                                             request.json["text"],
                                             request.json.get("startOffset"),
                                             request.json.get("endOffset"),
                                             cwi, ranker,
                                             requestId=request_id,
                                             min_similarity=min_similarity,
                                             blacklist=GENERIC_BLACKLIST)
    return make_response(statuscodes.OK,
                         "Simplification successful",
                         simplifications=simplifications,
                         request_id=request_id)


@app.route("/api/register_user", methods=["POST"])
def register_user():
    # get fields from request
    email = request.json["email"].lower()
    # pw_hash = request.json["pw_hash"]
    year_of_birth = request.json.get("year_of_birth", 1900)
    education = request.json.get("education", "N/A")
    # get maximum user ID
    logger.info("New user: {}".format([email, year_of_birth, education]))
    user = 1
    if user:
        msg = "Email address {} already registered".format(email)
        logger.info(msg)
        return make_response(statuscodes.EMAIL_ADDRESS_REGISTERED, msg)
    else:
        new_user_id = 1
        model_path = RANKER_PATH_TEMPLATE.format(new_user_id)
        return make_response(statuscodes.OK, "Registration successful")


@app.route("/api/login", methods=["POST"])
def login_user():
    email = request.json["email"].lower()
    logger.info("Received login request for user {}".format(email))
    user_id = 1
    if not user_id or user_id is None:
        msg = "Email address {} not found".format(email)
        logger.info(msg)
        return make_response(statuscodes.EMAIL_ADDRESS_NOT_FOUND, msg)
    msg = "OK. Logged on with email {}".format(email)
    logger.info(msg)
    # db_connection.update_last_login(user_id)
    return make_response(statuscodes.OK, "Login successful")


@app.route("/api/feedback", methods=["POST"])
def get_feedback():
    email = request.json["email"].lower()
    user_id = 1
    if not user_id or user_id is None:
        msg = "User ID not available for email address {}".format(email)
        logger.error(msg)
        return make_response(statuscodes.EMAIL_ADDRESS_NOT_FOUND, msg)
    simplifications = request.json.get("simplifications", None)
    feedback_text = request.json.get("feedback_text", "N/A")
    website = request.json.get("url", "N/A")
    # request_id = request.json.get("request_id", -1)
    rating = request.json.get("rating", 0)
    logger.info("Received feedback from user {}, rating {} for site {}. "
                "Feedback text: {}".format(email, rating, website,
                                           feedback_text))
    logger.debug("Request: {}".format(request.json))
    if simplifications:
        logger.info(simplifications)
        # try:
        logger.debug("Getting ranker for user: {}".format(user_id))
        ranker = get_personalized_ranker(user_id)
        logger.debug("Ranker: {}".format(ranker))
        update_ranker(ranker, user_id, simplifications, rating)
        return make_response(statuscodes.OK, "Feedback successful")
    else:
        msg = "Did not receive any simplifications"
        logger.info(msg)
        return make_response(statuscodes.NO_SIMPLIFICATIONS_RETURNED, msg)


@app.route("/api/test_connection", methods=["POST"])
def test_connection():
    logger.debug("Connection test from user {}".format(request.json["email"]))
    working_fine = True
    if working_fine:
        return make_response(statuscodes.OK, "Working fine.")
    else:
        return make_response(statuscodes.DATABASE_CONNECTION_ERROR,
                             "Something is wrong with the database.")


@app.route("/api/versioncheck", methods=["POST"])
def versioncheck():
    frontend_most_recent_version = cfg["frontend"]["most_recent_version"]
    download_url = cfg["frontend"]["download_url"]
    return make_response(statuscodes.OK,
                         "Returned most recent frontend version",
                         most_recent_version=frontend_most_recent_version,
                         download_url=download_url)


def get_personalized_ranker(user_id):
    if user_id in personalized_rankers:
        logger.info("Using personalized ranker, still in memory.")
        ranker = personalized_rankers[user_id]
    else:
        logger.info("Gotta load ranker or use default...")
        try:
            # retrieve model
            path = RANKER_PATH_TEMPLATE.format(user_id)
            ranker = LexiRanker.staticload(path)
        except:
            ranker = copy.copy(personalized_rankers["default"])
            ranker.set_userId(user_id)
        ranker.set_scorer(get_personalized_scorer(user_id))
        personalized_rankers[user_id] = ranker
    logger.info("Rankers in memory for users: {} (total number of {}).".format(
        list(personalized_rankers.keys()), len(personalized_rankers)))
    return ranker


def get_personalized_cwi(user_id):
    if user_id in personalized_cwi:
        logger.info("Using personalized cwi, still in memory.")
        cwi = personalized_cwi[user_id]
    else:
        logger.info("Gotta load cwi or use default...")
        try:
            # retrieve model
            path = CWI_PATH_TEMPLATE.format(user_id)
            cwi = LexiCWI.staticload(path)
        except:
            logger.warning("Could not load personalized model. "
                           "Loading default cwi.")
            cwi = copy.copy(personalized_cwi["default"])
            logger.debug(cwi)
            cwi.set_userId(user_id)
        cwi.set_scorer(get_personalized_scorer(user_id))
        personalized_cwi[user_id] = cwi
    return cwi


def get_personalized_scorer(user_id):
    logger.debug("Getting personalized scorer for user {}. In memory? {}".format(user_id, user_id in personalized_scorers))
    if user_id in personalized_scorers:
        logger.info("Using personalized scorer, still in memory.")
        scorer = personalized_scorers[user_id]
        logger.debug("Scorer Featurizer: {}".format(hasattr(scorer, "featurizer")))
    else:
        logger.info("Gotta load scorer or use default...")
        try:
            # retrieve model
            path = SIMPLE_SCORER_PATH_TEMPLATE.format(user_id)
            scorer = SimpleLexiScorer.staticload(path)
        except:
            logger.warning("Could not load personalized model. "
                           "Loading default scorer.")
            path = SIMPLE_SCORER_PATH_TEMPLATE.format('default')
            scorer = SimpleLexiScorer.staticload(path)
            scorer.set_userId(user_id)
            scorer.model_path = SIMPLE_SCORER_PATH_TEMPLATE.format(user_id)
        personalized_scorers[user_id] = scorer
    return scorer


if __name__ == "__main__":
    app.run(threaded=True)
    logger.debug("Rules: " + str([rule for rule in app.url_map.iter_rules()]))
else:
    application = app  # For GUnicorn
