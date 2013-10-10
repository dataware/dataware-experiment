from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
db_session = None

def init_db(url):
    global db_session
    # import all modules here that might define models so that
    # they will be registered properly on the metadata.  Otherwise
    # you will have to import them first before calling init_db()
    engine = create_engine(url, convert_unicode=True,  pool_recycle=3600, echo_pool=True)
    db_session = scoped_session(sessionmaker(autocommit=False,autoflush=True,bind=engine))
    Base.query = db_session.query_property()
    import models
    Base.metadata.create_all(bind=engine)

