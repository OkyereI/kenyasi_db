# config.py

import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_very_secret_key_that_you_should_change_in_production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'instance', 'community.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Arkesel SMS API Configuration
    ARKESEL_API_KEY = os.environ.get('ARKESEL_API_KEY') or 'b0FrYkNNVlZGSmdrendVT3hwUHk'
    ARKESEL_SENDER_ID = 'K1YouthAss' # Or your registered sender ID


