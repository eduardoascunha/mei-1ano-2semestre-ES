import threading
import time
from servidor.DBManager import DBManager

def verificar_integridade_todos_ficheiros():
    cursor = DBManager()
    
    # Obter os IDs de todos os ficheiros
    ficheiros_ids = cursor.obter_todos_ficheiros_ids_bd()
    
    ficheiros_corrompidos = []
    
    for ficheiro_id in ficheiros_ids:
        if not cursor.verificar_integridade_ficheiro(ficheiro_id):
            ficheiros_corrompidos.append(ficheiro_id)
            print(f"[ALERTA] Ficheiro {ficheiro_id} corrompido")
    
    if not ficheiros_corrompidos:
        print("[OK] Todos os ficheiros estão íntegros.")
    
    # Voltar a agendar a execução daqui a 120 segundos
    threading.Timer(60, verificar_integridade_todos_ficheiros).start()