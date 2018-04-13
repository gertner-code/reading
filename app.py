#!/usr/bin/env python


"""First iteration of website designed to catalog books of interest."""

from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Genre, Book, User, Base
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
    open('g_client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Reading Catalog"

# Connect to Database and create database session

engine = create_engine('sqlite:///reading_catalog.db')
DBSession = sessionmaker(bind=engine)
session = DBSession()
Base.metadata.bind = engine


# Shows Genres in a list
@app.route('/')
@app.route('/home')
def home():
    """Home page, show list of genres."""
    genres = session.query(Genre).order_by(asc(Genre.name))
    return render_template('home.html', genres=genres)

# Login section


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    """Show login page."""
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """Connect with Facebook."""
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data.decode('utf8')
    print("access token received %s ") % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (  # NOQA
        app_id, app_secret, access_token))
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    """
        Due to the formatting for the result from the server token exchange we
        have to split the token first on commas and select the first index
        which gives us the key : value for the server access token then we
        split it on colons to pull out the actual token value and replace the
        remaining quotes with nothing so that it can be used directly in the
        graph api calls
    """
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token  # NOQA
    h = httplib2.Http()
    result = h.request(url, 'GET')[1].decode('utf-8')
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id


@app.route('/fbdisconnect')
def fbdisconnect():
    """Disconnect with Facebook."""
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = ('https://graph.facebook.com/%s/permissions?access_token=%s' %
           (facebook_id, access_token))
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Login in with Google."""
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('g_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1].decode('utf-8'))
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already '
                                            'connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    return str(user_id)

# User Helper Functions


def createUser(login_session):
    """Create new user."""
    newUser = User(email=login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """Get user info from OAuth."""
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """Check for existance of user in User table."""
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    """Disconnect Google user."""
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps("""Failed to revoke token for given
                                               user."""), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    """Disconnect based on log-in provider."""
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
            del login_session['user_id']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            del login_session['email']
            del login_session['user_id']
            del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('home'))
    else:
        flash("You were not logged in")
        return redirect(url_for('home'))


@app.route('/<int:genre_id>/')  # shows books in genre
@app.route('/<int:genre_id>/books')
def showBooks(genre_id):
    """Show books in selected genre."""
    genre = session.query(Genre).filter_by(id=genre_id).one()
    books = session.query(Book).filter_by(genre_id=genre_id).all()
    if 'user_id' not in login_session:
        return render_template('publicBooks.html', books=books, genre=genre)
    else:
        return render_template('showBooks.html', books=books, genre=genre,
                               user=login_session['user_id'])


@app.route('/<int:genre_id>/new', methods=['GET', 'POST'])
def newBook(genre_id):
    """Add new book to DB."""
    if 'user_id' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newBook = Book(
                        title=request.form['title'],
                        user_id=login_session['user_id'],
                        author=request.form['author'],
                        synopsis=request.form['synopsis'],
                        genre_id=genre_id
                      )
        session.add(newBook)
        flash('%s Successfully Added' % newBook.title)
        session.commit()
        return redirect(url_for('showBooks', genre_id=genre_id))
    else:
        return render_template('newBook.html')


@app.route('/<int:genre_id>/<int:id>/edit', methods=['GET', 'POST'])
def editBook(genre_id, id):
    """Allow editting of books entered by the current user."""
    if 'user_id' not in login_session:
        return redirect('/login')
    editedBook = session.query(Book).filter_by(id=id).one()
    if login_session['user_id'] != editedBook.user_id:
        return """<script>function myFunction() {alert('You are not authorized
               to edit this book. A book can only be editted by the user that
               added it.');}</script><body onload='myFunction()'>"""
    if request.method == 'POST':
        if request.form['title']:
            editedBook.title = request.form['title']
        if request.form['author']:
            editedBook.author = request.form['author']
        if request.form['synopsis']:
            editedBook.synopsis = request.form['synopsis']
        session.add(editedBook)
        session.commit()
        flash('Book Successfully Edited')
        return redirect(url_for('showBooks', genre_id=genre_id))
    else:
        return render_template('editBook.html', genre_id=genre_id, id=id,
                               book=editedBook)


@app.route('/<int:genre_id>/<int:id>/delete', methods=['GET', 'POST'])
def deleteBook(genre_id, id):
    """Allow a user to delete a book they have previously entered."""
    if 'user_id' not in login_session:
        return redirect('/login')
    bookToDelete = session.query(Book).filter_by(id=id).one()
    if login_session['user_id'] != bookToDelete.user_id:
        return """<script>function myFunction() {alert('You are not authorized
                  to delete this book. A book can only be deleted by the user
                  that added it.');}</script><body onload='myFunction()'>"""
    if request.method == 'POST':
        session.delete(bookToDelete)
        session.commit()
        flash('Book Successfully Deleted')
        return redirect(url_for('showBooks', genre_id=genre_id))
    else:
        return render_template('deleteBook.html', genre_id=genre_id, id=id,
                               book=bookToDelete)


@app.route('/<int:genre_id>/<int:id>/details')
def bookDetails(genre_id, id):
    """Show full details of slected book."""
    book = session.query(Book).filter_by(id=id).one()
    if 'user_id' not in login_session or login_session['user_id'] != book.user_id:  # NOQA
        return render_template('bookDetails.html', book=book)
    else:
        return render_template('bookDetails_withLinks.html', genre_id=genre_id,
                               id=id, book=book, user=login_session['user_id'])

# JSON API Endpoints


@app.route('/books/<int:id>/JSON')
def bookJSON(id):
    """Return details of requested book."""
    book = session.query(Book).filter_by(id=id).one()
    return jsonify(Book=book.serialize)


@app.route('/books/<int:genre_id>/JSON')
def genreJSON(genre_id):
    """Return details of all books in requested genre."""
    books = session.query(Book).filter_by(genre_id=genre_id).all()
    return jsonify(Book=[book.serialize for book in books])


@app.route('/books/JSON')
def allbooksJSON():
    """Return details of all books broken up by genre."""
    books = session.query(Book).all()
    return jsonify(Book=[book.serialize for book in books])


if __name__ == '__main__':
    """Run webpage on open."""
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
