import random
from socket import socket, AF_INET, SOCK_STREAM
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def criaCipher(chave,iv, backend):
    #cria o objeto de criptografia a partir da chave
    aes = algorithms.AES(chave)
    #cria o modo de inicialização 
    cbc = modes.CBC(iv)
    #cria o cipher 
    cipher = Cipher(aes,cbc,backend=backend)

    return cipher



def critogrtafiaAES(mensagem, chave, iv, backend): # funcao de criptografia
    #Ajusta a menssagem enviada para ser multipla de 16
    tamanhoBloco = 16
    n = len(mensagem)
    addEspaco = tamanhoBloco - n % tamanhoBloco
    novaMensagem = bytearray(mensagem + ' '*addEspaco, encoding="utf8")
    
    cipher = criaCipher(chave, iv, backend)
    #pega o encriptador a partir do cipher 
    encriptador = cipher.encryptor()
    #Encripta a mensagem
    mensagemCriptografada = encriptador.update(novaMensagem) + encriptador.finalize()

    return mensagemCriptografada



def descriptografiaAES(mensagemCriptografada, chave, iv, backend): #funcao de descriptografia
    cipher = criaCipher(chave, iv, backend)
    decriptografador = cipher.decryptor()
    decriptografador.update(mensagemCriptografada) + decriptografador.finalize
    mensagemDescriptografada = mensagemCriptografada

    return mensagemDescriptografada



def CriaGeradores(): #criou o gerador e primo comum aos dois
    geradorPrimo = random.randint(1,1000)
    gerador = random.randint(1,1000)

    while not primo(geradorPrimo):
        geradorPrimo = random.randint(1,1000)
    return geradorPrimo, gerador 

def primo(n): #função para verificar se é primo
    for i in range(2,n):
        if n % i == 0:
            return False
    return True

mClientSocket = socket(AF_INET, SOCK_STREAM)
mClientSocket.connect(('localhost', 1235))

geradorPrimo, gerador = CriaGeradores()
#Envia essas chaves para o servidor
chavesPrimoGerador = (f'chaves {geradorPrimo} {gerador}')
mClientSocket.send(chavesPrimoGerador.encode())

#O cliente recebe uma mensagem aprovando que o servidor
#recebeu o gerador e o primo
confimacao = mClientSocket.recv(2048)
req = confimacao.decode()
print(req)

if req == 'Chaves OK':
    #Cria uma chave confidencial do cliente
    chaveConfidencialCliente = random.randint(0,1000)
    #Executa o primeiro dieff hellman e envia para o servidor sua chave publica do cliente o rep1
    rep1 = (gerador**(chaveConfidencialCliente))%geradorPrimo
    mClientSocket.send(str(rep1).encode())

    #Recebe a chave publica do servidor 
    data1 = mClientSocket.recv(2048)
    req1 = data1.decode()
    chavePublicaServidor = int(req1)
    print(f'Chave publica do servidor = {chavePublicaServidor}')

    #gera a chave compartihada do cliente e servidor
    chaveCompartilhada = (chavePublicaServidor**chaveConfidencialCliente)%geradorPrimo
    print(f'chave compartilhada = {chaveCompartilhada}')

    #Envia para o servidor a chave compartilhada
    mClientSocket.send(str(chaveCompartilhada).encode())
    #Recebe a chave compartilhada do servidor
    data2 = mClientSocket.recv(2048)
    req2 = data2.decode()

    data3 = mClientSocket.recv(2048)
    req3 = data3.decode()
    chaveIvBackend = req3.split(' ')
    chave = chaveIvBackend[0]
    iv = chaveIvBackend[1]
    backend = chaveIvBackend[2]

#Começa a transferencia dos dados e verifica se a chave compartilhada recebeida é a mesma enviada
while True and req2 == str(chaveCompartilhada):
    # Este loop foi criado apenas para que o cliente conseguisse enviar múltiplas solicitações
    mensagem = input('>>')
    #criptografa a mensagem recebida 
    mensagemCriptografada = critogrtafiaAES(mensagem,chave,iv,backend)
    #Envia a mensagem criptografada pelo socket criado.
    mClientSocket.send(mensagemCriptografada.encode())
    #Recebendo as respostas do servidor.
    data = mClientSocket.recv(2048)
    reply = data.decode()
    #descriptografa a mensagem recebida
    mensagemDescriptografada = descriptografiaAES(reply, chave, iv, backend)
    print(f'Resposta recebida:{reply}')

