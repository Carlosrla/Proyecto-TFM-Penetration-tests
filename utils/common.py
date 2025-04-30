import sys
import termios

def restaurar_stdin():
    try:
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception as e:
        print(f"[!] Error restaurando entrada estándar: {e}")