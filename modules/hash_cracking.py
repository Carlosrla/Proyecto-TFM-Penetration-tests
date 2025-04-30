
import subprocess
import os
import json

def crack_hashes(hashes_file, wordlist_path, output_path="results/smb/creds.json"):
    """
    Crackea hashes NTLMv2 usando Hashcat con el modo apropiado.
    Guarda las credenciales crackeadas en formato JSON.
    """

    cracked_file = "results/hashcat_cracked.txt"

    # Asegurar carpetas
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Vaciar salida anterior
    print("[*] Limpiando resultados anteriores de Hashcat...")
    open(cracked_file, "w").close()

    # Comando Hashcat
    hashcat_cmd = [
        "hashcat", "-m", "5600", hashes_file, wordlist_path,
        "--potfile-disable", "--outfile", cracked_file, "--quiet"
    ]

    print("[*] Ejecutando Hashcat para crackear hashes NTLMv2...")

    try:
        result = subprocess.run(hashcat_cmd, capture_output=True, text=True)
    except Exception as e:
        print(f"[!] Error al ejecutar Hashcat: {e}")
        return None

    # Verificar si el archivo de salida tiene contenido
    if not os.path.exists(cracked_file) or os.path.getsize(cracked_file) == 0:
        print("[-] No se pudo crackear ningún hash.")
        return None

    # Leer y guardar resultados en JSON
    credenciales = []
    with open(cracked_file, "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) >= 2:
                username = parts[0]
                password = parts[-1]
                credenciales.append({"usuario": username, "password": password})

    if not credenciales:
        print("[-] Hashcat no logró crackear ninguna credencial.")
        return None

    with open(output_path, "w") as out:
        json.dump(credenciales, out, indent=4)

    print(f"[+] {len(credenciales)} credencial(es) crackeada(s) guardadas en {output_path}")
    return credenciales
