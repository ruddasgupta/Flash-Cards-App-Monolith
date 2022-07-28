import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    #Auth
    SECRET_KEY = 'thisissecret'
    #DB
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'cards.db')