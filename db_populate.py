from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Restaurant, Base, MenuItem, User

engine = create_engine('sqlite:///reading_catalog.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()


# Create dummy user (just adding my email for easy testing later)
User1 = User(email="gertner.code@gmail.com")
session.add(User1)
session.commit()

#Add Genres
category1 = Genre(name="Science Fiction")
session.add(category1)
session.commit()

category2 = Genre(name="Fantasy")
session.add(category2)
session.commit()

category3 = Genre(name="Mystery")
session.add(category3)
session.commit()
