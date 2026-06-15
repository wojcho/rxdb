from sqlalchemy import inspect
from app.db import engine, SessionLocal, Base

def reflect_db():
    # reflect all tables
    Base.prepare(autoload_with=engine)

    print("Reflected tables:")
    print(Base.classes.keys())

    return Base


def run_query():
    Base = reflect_db()

    session = SessionLocal()

    # Example: access a reflected table dynamically
    # Suppose you have a table called "users"
    if "users" in Base.classes:
        Users = Base.classes.users

        users = session.query(Users).all()

        for u in users:
            print(u)

    session.close()


if __name__ == "__main__":
    run_query()

