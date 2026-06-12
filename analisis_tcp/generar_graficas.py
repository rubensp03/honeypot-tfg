import pandas as pd
import matplotlib.pyplot as plt
import re

DATA_FILE = 'data.txt'

def process_data():
    times = []
    ports = []
    
    # Expresión regular para extraer la hora y el puerto de destino
    # Ejemplo de línea: 16:37:44.809861 IP 170.187.165.242.58207 > 159.223.6.94.449: tcp 0
    # Group 1: Time, Group 2: DstPort
    regex = re.compile(r'^(\d{2}:\d{2}:\d{2})\.\d+ IP (?:[\d\.]+)\.\d+ > (?:[\d\.]+)\.(\d+): tcp')
    
    with open(DATA_FILE, 'r') as f:
        for line in f:
            match = regex.search(line)
            if match:
                times.append(match.group(1))
                ports.append(match.group(2))
                
    df = pd.DataFrame({'time': times, 'port': ports})
    
    if df.empty:
        print("No se encontraron datos que coincidan con la expresión regular.")
        return

    # Convertimos 'time' a formato datetime para la gráfica (solo usamos la parte de la hora)
    df['time'] = pd.to_datetime(df['time'], format='%H:%M:%S')
    
    # --- Gráfica 1: Líneas (Volumen a lo largo del tiempo) ---
    # Agrupamos por intervalos de 10 segundos para ver los picos
    df_volume = df.set_index('time').resample('10s').size()
    
    plt.figure(figsize=(12, 6))
    df_volume.plot(kind='line', color='red', linewidth=1.5)
    plt.title('Volumen de Paquetes TCP Entrantes (Intervalos de 10s)')
    plt.xlabel('Hora de Captura')
    plt.ylabel('Cantidad de Paquetes')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig('grafica_volumen_tiempo.png')
    plt.close()
    print("Generada gráfica de volumen en 'grafica_volumen_tiempo.png'")
    
    # --- Gráfica 2: Circular (Puertos más escaneados) ---
    port_counts = df['port'].value_counts()
    
    # Obtenemos el Top 10 y agrupamos el resto en "Otros"
    top_n = 10
    top_ports = port_counts.head(top_n)
    
    if len(port_counts) > top_n:
        others_count = port_counts.iloc[top_n:].sum()
        others = pd.Series({'Otros': others_count})
        plot_data = pd.concat([top_ports, others])
    else:
        plot_data = top_ports
    
    plt.figure(figsize=(10, 8))
    plt.pie(plot_data, labels=plot_data.index, autopct='%1.1f%%', startangle=140, 
            colors=plt.cm.tab20.colors)
    plt.title('Top 10 Puertos Más Escaneados')
    plt.tight_layout()
    plt.savefig('grafica_top_puertos.png')
    plt.close()
    print("Generada gráfica circular en 'grafica_top_puertos.png'")

if __name__ == "__main__":
    process_data()
