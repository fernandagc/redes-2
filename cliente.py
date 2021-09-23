import socket
import sys
import pyDH
import json
import random
import string
import pyDes
import base64
#Esperando conexão do servidor
#.decode é usado pra transformar bytes em string
def receive(socket, signal):
    while signal:
        try:
            data = socket.recv(32)
            print('Aguardando servidor', file=arquivo)
        except:
            print("Você foi desconectado", file=arquivo)
            signal = False
            break

arquivo = open('log_cliente.log', 'w+')
#Pega o host e a porta
server_address = ('localhost', 10000)

#Tentativa de conexão com o servidor
try:
	print("Tentando conectar ao servidor...", file=arquivo)
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(server_address)
	print("Conexão estabelecida com o servidor", server_address, file=arquivo)
except:
    print("Não foi possível conectar ao servidor", server_address, file=arquivo)
    input("Aperte 'enter' para sair", file=arquivo)
    sys.exit(0)	

d2 = pyDH.DiffieHellman()

# Step1: recebe a chave compartilhada e a chave publica do servidor
print("Recebendo a chave compartilhada e a chave publica do servidor...", file=arquivo)
step1 = sock.recv(1024)
print("Chave recebida com sucesso", file=arquivo)
# Step 1.1: Analisando as palavras das chaves
jsonData = json.loads(step1.decode("utf-8"))
jsonData = jsonData["dh-keyexchange"]

# chave compartilhada e chave publica do server
sharedPrime = jsonData["prime"]
publicSecretServidor = jsonData["publicSecret"]
valor = 0
testess = 1
letters = string.ascii_letters

print("Digite o numero de mensagens que deseja enviar:")
testes = input()
if not testes.isdigit():
	while not testes.isdigit():
		print("Digite apenas numeros inteiros:")
		testes = input()
print("Iniciando envios das",testes, "mensangens de testes... \n", file=arquivo)
# transformando o valor pra inteiro
testes = int(testes)
print("Enviando....")
print("....................")
print("............................")
while testess <= testes:
    # message = input()
	print("Gerando o tamanho da mensagem à ser enviada...", file=arquivo)
	tamanho = (random.randrange(10,100))
	message = ''.join(random.choice(letters) for i in range(tamanho))
	print("Iniciando processo para o envio da mensagem",testess, file=arquivo)
	print("Calculando as chaves compartilhadas à partir da chave publica do servidor...", file=arquivo)
	# step3: calcula as chave compartilhada a partir da chave publica do servidor
	chaveCompartilhadaCalculadaApartirDaChaveDoServidor = d2.gen_shared_key(publicSecretServidor)
	print("Chave calculada com sucesso", file=arquivo)
	# Step2: calcula a chave publica e manda para o servidor
	print("Calculando a chave publica à ser enviada ao servidor...", file=arquivo)
	calcedPubSecret = str(d2.gen_public_key())
	print("Calculo efetuada com sucesso", file=arquivo)
	calcedPubSecret1 = str("1221321321321")
	print("Iniciando empacotamento das mensanges....", file=arquivo)
	step2 = "{"
	step2 += "\"dh-keyexchange\":"
	step2 += "{"
	step2 += "\"step\": {},".format(2)
	valor = (random.randrange(0, 5))
	resto = valor % 2
	if resto == 0: 
		step2 += "\"publicSecret\": {},".format(calcedPubSecret) 
	else:
		print("Empacotando junto da mensagem uma chave pública errada afim de ser testada a segurança no servidor...", file=arquivo)
		step2 += "\"publicSecret\": {},".format(calcedPubSecret1)   
	step2 += "\"chaveCompartilhadaCalculada\": \"{}\",".format(chaveCompartilhadaCalculadaApartirDaChaveDoServidor)
	print("Criando a chave da criptografia....", file=arquivo)
	key = chaveCompartilhadaCalculadaApartirDaChaveDoServidor[0:8]
	print("Iniciando a criptografia da mensagem \"", message, '\"', file=arquivo)
	k = pyDes.des(key, pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
	d = k.encrypt(message)
	print("Mensagem criptografada com sucesso!!!", file=arquivo)
	troca_base = base64.encodebytes(d)
	step2 += "\"mensagem\": \"{}\"".format(troca_base)
	step2 += "}}"
	print('Mensagem empacotada com sucesso!!!!', file=arquivo)
	print('Enviando mensagem de numero', testess, 'e tamanho', tamanho, 'ao servidor...', file=arquivo)
	sock.send(step2.encode())
	print('Mensagem enviada com sucesso!!!\n', file=arquivo)
	testess = testess + 1

print("Mensagens enviadas com sucesso, verifique os logs para mais detalhes.")