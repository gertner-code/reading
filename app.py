from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Books Catalog"

#Shows Genres in a list
@app.route('/')
@app.route('/home')
def home():

#Login section

@app.route('/login')
def showLogin():



@app.route('/<int:genre_id>/books') #shows books in genre
@app.route('/<string:author>/books') #shows books by clicked Author
def showBooks():

@app.route('/new')
def newBook():

@app.route('/<int:genre_id>/<int:id>/edit', methods=['GET', 'POST'])
def editBook(id):

@app.route('/<int:genre_id>/<int:id>/delete', methods=['GET', 'POST'])
def deleteBook(id):

@app.route('/<int:genre_id>/<int:id>/details')
def bookDetails(id):


#JSON API Endpoints

@app.route('books/<int:id>/JSON')
def bookJSON(id):
"""Returns details of requested book."""
@app.route('books/JSON')
def allbooksJSON():
"""Returns details of all books broken up by genre."""


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
