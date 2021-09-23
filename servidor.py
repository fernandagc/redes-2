import socket
import sys
import pyDH
import json
import base64
import pyDes

arquivo = open('log_servidor.log', 'w+')
# Cria TCPIP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Faz a conexão
server_address = ('localhost', 10000)
print('Estabelecendo conexao com %s porta %s' % server_address, file=arquivo)
sock.bind(server_address)
print('Conexão estabelecida com sucesso!!!', file=arquivo)
# Fica escutando conexoes
sock.listen(1)

# Usa a biblioteca do algoritmo DiffieHellman para calcular o valor que será usado para realizar
# os calculos das chaves
d1 = pyDH.DiffieHellman()
num_mensagens = 1
arquivo.close()
while True:
    # Aguarda conexões
    arquivo = open('log_servidor.log', 'a+')
    print('Esperando conexões', file=arquivo)
    connection, client_address = sock.accept()
    print('Conexão aceita', file=arquivo)
    try:
        print('Conexão de: ', client_address,'estabelecida', file=arquivo)

        #Começa a criptografia e calculo das chaves
        print('Iniciando o caclulo das chaves secretas....', file=arquivo)
        publicSecret = d1.gen_public_key()
        d1_sharedkey = d1.gen_shared_key(publicSecret)
        print('Calculos das chaves feito com sucesso!!!', file=arquivo)
        print('Iniciando o compartilhamento da chave publica e chave compartilhada do servidor....', file=arquivo)
        print('Iniciando o empacotamento da mensagem....', file=arquivo)
        # Step1: compartilha chave publiva e compartilhada do server
        step1 = "{"
        step1 += "\"dh-keyexchange\":"
        step1 += "{"
        step1 += "\"step\": {},".format(1)
        step1 += "\"prime\": \"{}\",".format(d1_sharedkey)
        step1 += "\"publicSecret\": {}".format(publicSecret)
        step1 += "}}"            
        print('Mensagem com as chaves empacotadas!!!', file=arquivo)
        connection.send(step1.encode())
        print('Chaves compartilhadas!!!', file=arquivo)
        conexao = 1
        # Recebendo os dados em pequenos pedaços e os retransmita
        while conexao:
            try:          
                step2 = connection.recv(1024)
                # step 2.1  análise das palavras
                jsonData = json.loads(step2.decode("utf-8"))
                jsonData = jsonData["dh-keyexchange"]
                print('Iniciando recebimento da mensagem', num_mensagens, file=arquivo) 
                print('Iniciando a análise das chaves recebidas...', file=arquivo)
                print('Analisando mensagem...', file=arquivo)
                # pega a mensagem
                mensagem = str(jsonData["mensagem"])           

                print('Analisa chave publica do cliente...', int(jsonData["publicSecret"]), file=arquivo)
                # recebe a chave publica do servidor
                publicSecretCliente = int(jsonData["publicSecret"])  

                print('Analisa a chave compartilhada do cliente...', file=arquivo)
                # pega a chave compartilhada calculada la no lado do cliente pra ver se vai ser igual         
                chaveCompartilhadaCalculadaNoCliente = str(jsonData["chaveCompartilhadaCalculada"])          

                print('Calculando a chave compartilhada à partir da chave pública do cliente...', file=arquivo)
                # Step3:  calcula as chave compartilhada a partir da chave publica do cliente, se for errada ele continua para tratar erro mais tarde
                chaveCompartilhadaCalculadaAPartirDaChaveDoCliente = "";
                try:
                    chaveCompartilhadaCalculadaAPartirDaChaveDoCliente = d1.gen_shared_key(publicSecretCliente)
                except:
                    #print("Chave errada, mensagem recusada.")
                    pass            
                print('Chaves calculadas com sucesso!!!', file=arquivo)    
                if chaveCompartilhadaCalculadaAPartirDaChaveDoCliente == chaveCompartilhadaCalculadaNoCliente :
                    print('Chaves corretas, descriptografando arquivos...', file=arquivo)
                    key = chaveCompartilhadaCalculadaAPartirDaChaveDoCliente[0:8]
                    k = pyDes.des(key, pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
                    d = base64.decodebytes(mensagem[2:-1].encode())
                    d = k.decrypt(d)
                    print('Mensagem de número',num_mensagens, 'descriptografada com sucesso:', d, file=arquivo)
                    #print(mensagem)
                else:
                    print('Chaves incorretas, mensagem de número',num_mensagens, 'recusada', file=arquivo)

                num_mensagens = num_mensagens + 1
                print('', file=arquivo)
            except:
                conexao = 0
                connection.close()
                arquivo.close()
    finally:
        # Clean up the connection
        connection.close()