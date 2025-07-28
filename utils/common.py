import sys  # Para acceder a la entrada estándar (stdin)
import termios  # Para manejar configuraciones del terminal en sistemas UNIX/Linux

def restaurar_stdin():
    """
    Limpia el búfer de entrada estándar (stdin).
    Esto es útil después de ejecutar herramientas que pueden dejar
    la entrada en estado inconsistente (por ejemplo, procesos en segundo plano).
    """
    try:
        # Vacía el búfer de entrada pendiente en stdin (como pulsaciones de teclas anteriores)
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception as e:
        # En caso de error (por ejemplo, si no es un terminal interactivo), lo informa
        print(f"[!] Error restaurando entrada estándar: {e}")
