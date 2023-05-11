import sqlite3
import csv
import pandas as pd

#Para poner los datos del csv en la Base de datos

conn = sqlite3.connect('bd.db')

cursor = conn.cursor()
cursor.execute('''CREATE TABLE alertas
                   (timestamp datetime, sid int, msg text, clasification text, priority int, protocol text, origin text, destination text, port int)''')

with open('alerts.csv', newline='') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        cursor.execute("INSERT INTO alertas (timestamp, sid, msg, clasification, priority, protocol, origin, destination, port) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", row)

conn.commit()
conn.close()