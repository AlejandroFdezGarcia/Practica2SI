import sqlite3
import csv
import pandas as pd
from flask import Flask, render_template
import matplotlib.pyplot as plt

app = Flask(__name__)

@app.route('/top_ips/<int:x>')
def top_ips(x):
    con = sqlite3.connect('bd.db')
    cur = con.cursor()
    cur.execute(f"SELECT origin, COUNT(*) FROM alertas WHERE priority = 1 GROUP BY origin ORDER BY COUNT(*) DESC LIMIT {x}")

    results = cur.fetchall()
    con.close()

    ips = [result[0] for result in results]
    counts = [result[1] for result in results]

    plt.bar(ips[:x], counts[:x])  # Limitar a los primeros x elementos
    plt.xlabel('IPs de origen')
    plt.ylabel('Número de incidencias')
    plt.title(f'Top {x} IPs de origen con mayor número de incidencias (prioridad = 1)')

    # Guardar el gráfico en un archivo
    graph_file = 'static/graph.png'
    plt.savefig(graph_file, format='png')
    plt.close()

    # Renderizar la plantilla HTML con la ruta al archivo del gráfico
    return render_template('graph.html', graph_file=graph_file)


@app.route('/top_devices/<int:x>')
def top_devices(x):
    con = sqlite3.connect('bd.db')
    cur = con.cursor()
    cur.execute(f"SELECT origin, COUNT(*) FROM alertas WHERE priority = 1 GROUP BY origin ORDER BY COUNT(*) DESC LIMIT {x}")

    results = cur.fetchall()
    con.close()

    devices = [result[0] for result in results]
    counts = [result[1] for result in results]

    plt.bar(devices[:x], counts[:x])  # Limitar a los primeros x elementos
    plt.xlabel('Dispositivos')
    plt.ylabel('Número de incidencias')
    plt.title(f'Top {x} dispositivos más vulnerables (prioridad = 1)')

    # Guardar el gráfico en un archivo
    graph_file = 'static/graph.png'
    plt.savefig(graph_file, format='png')
    plt.close()

    # Renderizar la plantilla HTML con la ruta al archivo del gráfico
    return render_template('graph.html', graph_file=graph_file)


if __name__ == '__main__':
    app.run()