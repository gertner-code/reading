#Reading Catalog

##Notes
* Due to changes in Facebook's policy their OAuth can only be run if the page is encrypted using https.
* If you would like to run it from localhost try using [this.](https://github.com/madeny/lhttps)  

##Project Description
* A website to catalog books to read in the 3 genres I am most interested in.
* A website generated using flask templates to view, edit, and delete entries from a database
* uses OAuth2.0 to confirm users
* uses SQLAlchemy orm to interact with the sqlite database

##Requirements
* sqlite
* SQLAlchemy
* OAuth2client
* Python3


##Database Schema

###Genre
* name
* id

###Book
* Title
* Author/s
* Synopsis
* id
* user_id
* genre_id

###User
* email
* id

##Setup
1. download files in github.
1. install all Requirements.
1. run app.py.
1. go to localhost:5000/ to access front page.
1. to add, edit, or delete from the db first login by clicking login in the top right corner.
1. db is included but if problems occur concerning database run database_setup.py and db_populate.py.
