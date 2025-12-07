import mysql.connector

def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="qebfix-fiqgy4-kabGim",
        database="final_testing_lms_db1"
    )
