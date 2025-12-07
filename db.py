import mysql.connector

def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="MySQL123",
        database="final_testing_lms_db"
    )
