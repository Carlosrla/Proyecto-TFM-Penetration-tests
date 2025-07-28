import subprocess  # Para ejecutar comandos externos como Hashcat
import os  # Para manejar rutas y verificar/crear directorios
import json  # Para guardar resultados en formato JSON

def crack_hashes(hashes_file, wordlist_path, output_path="results/smb/creds.json"):
    """
    Crackea hashes NTLMv2 usando Hashcat con el modo apropiado (5600 para NTLMv2).
    Guarda las credenciales crackeadas en un archivo JSON.
    """

    # Archivo donde Hashcat guardará los hashes crackeados
    cracked_file = "results/smb/hashcat_cracked.txt"

    # Asegura que el directorio del archivo de salida existe
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Limpia el archivo anterior de resultados de Hashcat (si existe)
    print("[*] Limpiando resultados anteriores de Hashcat...")
    open(cracked_file, "w").close()

    # Comando de Hashcat para crackear hashes NTLMv2 con el modo 5600
    hashcat_cmd = [
        "hashcat", "-m", "5600", hashes_file, wordlist_path,
        "--potfile-disable",  # No guarda el progreso en el archivo .potfile
        "--outfile", cracked_file,  # Archivo de salida con los hashes crackeados
        "--quiet"  # Ejecuta sin mostrar mensajes adicionales
    ]

    # Muestra que se inicia el proceso de cracking
    print("[*] Ejecutando Hashcat para crackear hashes NTLMv2...")

    try:
        # Ejecuta el comando hashcat y captura salida/errores
        result = subprocess.run(hashcat_cmd, capture_output=True, text=True)
    except Exception as e:
        # Si falla el comando, muestra el error y finaliza
        print(f"[!] Error al ejecutar Hashcat: {e}")
        return None

    # Verifica si el archivo de salida existe y tiene contenido
    if not os.path.exists(cracked_file) or os.path.getsize(cracked_file) == 0:
        print("[-] No se pudo crackear ningún hash.")
        return None

    # Lista donde se almacenarán las credenciales extraídas
    credenciales = []
    with open(cracked_file, "r") as f:
        for line in f:
            # Divide cada línea por los ":" para obtener usuario y contraseña
            parts = line.strip().split(":")
            if len(parts) >= 2:
                username = parts[0]  # Parte izquierda (usuario/hash)
                password = parts[-1]  # Parte derecha (contraseña crackeada)
                credenciales.append({"usuario": username, "password": password})

    # Verifica si se extrajo al menos una credencial
    if not credenciales:
        print("[-] Hashcat no logró crackear ninguna credencial.")
        return None

    # Guarda las credenciales crackeadas en formato JSON
    with open(output_path, "w") as out:
        json.dump(credenciales, out, indent=4)

    # Informa cuántas credenciales fueron crackeadas
    print(f"[+] {len(credenciales)} credencial(es) crackeada(s) guardadas en {output_path}")
    return credenciales  # Devuelve la lista de credenciales
