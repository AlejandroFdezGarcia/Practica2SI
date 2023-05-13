import sqlite3
import csv
import requests
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for
import matplotlib.pyplot as plt

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/select_ips', methods=['GET', 'POST'])
def select_ips():
    if request.method == 'POST':
        num_ips = int(request.form['num_ips'])

        if num_ips > 0 and num_ips < 20:
            return redirect(url_for('top_ips', x=num_ips))
        else:
            return redirect(url_for('index'))

    return render_template('select_ips.html')
@app.route('/top_ips/<int:x>')
def top_ips(x):
    con = sqlite3.connect('bd.db')
    cur = con.cursor()
    cur.execute(f"SELECT origin, COUNT(*) FROM alertas WHERE priority = 1 GROUP BY origin ORDER BY COUNT(*) DESC LIMIT {x}")

    results = cur.fetchall()
    con.close()

    ips = [result[0] for result in results]
    counts = [result[1] for result in results]

    plt.bar(ips[:x], counts[:x])
    plt.xlabel('IPs de origen')
    plt.ylabel('Número de incidencias')
    plt.title(f'Top {x} IPs de origen con mayor número de incidencias (prioridad = 1)')

    graph_file = 'static/graph.png'
    plt.savefig(graph_file, format='png')
    plt.close()

    return render_template('graph.html', graph_file=graph_file, results=ips[:x])

@app.route('/select_devices', methods=['GET', 'POST'])
def select_devices():
    if request.method == 'POST':
        num_devices = int(request.form['num_devices'])

        if num_devices > 0 and num_devices < 20:
            return redirect(url_for('top_devices', x=num_devices))
        else:
            return redirect(url_for('index'))

    return render_template('select_devices.html')
@app.route('/top_devices/<int:x>')
def top_devices(x):
    conn = sqlite3.connect('bd.db')
    cursor = conn.cursor()

    query = """
    SELECT origin, COUNT(*) AS total
    FROM alertas
    GROUP BY origin
    ORDER BY total DESC
    """

    cursor.execute(query)
    results = cursor.fetchall()

    conn.close()

    devices = [result[0] for result in results[:x]]
    counts = [result[1] for result in results[:x]]

    plt.bar(devices, counts)
    plt.title(f"Top {x} dispositivos más vulnerables")
    plt.xlabel("Dispositivo")
    plt.ylabel("Número de alertas")

    graph_file = 'static/graph.png'
    plt.savefig(graph_file, format='png')
    plt.close()

    return render_template('graph.html', graph_file=graph_file, results=devices)

@app.route('/top_dangerous')
def top_dangerous():
    conn = sqlite3.connect('bd.db')
    cursor = conn.cursor()

    query = """
    SELECT id, analisis_servicios, analisis_serviciosinseguros
    FROM dispositivos
    """

    cursor.execute(query)
    results = cursor.fetchall()

    conn.close()

    devices = []
    unsafe_service_ratios = []

    for result in results:
        device = result[0]
        total_services = result[1]
        unsafe_services = result[2]

        if total_services > 0 and (unsafe_services / total_services) > 0.33:
            devices.append(device)
            unsafe_service_ratio = unsafe_services / total_services
            unsafe_service_ratios.append(unsafe_service_ratio)

    plt.figure(figsize=(10, 6))
    plt.bar(devices, unsafe_service_ratios)
    plt.xlabel('Dispositivos')
    plt.ylabel('Proporción de servicios inseguros')
    plt.title('Top de dispositivos peligrosos')

    graph_file = 'static/graph.png'
    plt.savefig(graph_file, format='png')
    plt.close()

    return render_template('graph.html', graph_file=graph_file, results=devices)

@app.route('/sobaco')
def vulnerabilities():
    vulner=requests.get("https://cve.circl.lu/api/last")
    return render_template('vulnerabilities.html', vulner=vulner)



if __name__ == '__main__':
    app.run()