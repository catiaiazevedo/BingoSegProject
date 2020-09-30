from base64 import b64encode

import Security
import socket
import threading
import random
import json
import sys
import os


"""
A função authenticate inicia o
protocolo de autenticação
"""
def authentication_stage():
    print('Fase de autenticação:\n')
    send_auth0()
    receive_auth1()
    send_auth2()
    print('Autenticado com sucesso!\nÀ espera que o jogo comece ...')


def send_auth0():
    # preparar a mensagem auth0
    message = dict()
    message['type'] = 'AUTH0'
    message['id'] = ID
    message['nonce'] = Security.nonce()
    message['session_key'] = SESSION_KEY
    message['hashed_public_key'] = Security.shaHash(Security.rsaDumpKey(PUBLIC_KEY))

    # encriptar a mensagem auth0 com a public key do manager
    plainText = json.dumps(message).encode()
    cipherText = Security.rsaEncrypt(plainText,SERVER_PUBLIC_KEY)

    # enviar a mensagem auth0 ao manager
    MANAGER_SOCKET.sendall(cipherText)
    SENT_MESSAGES.append(message)


def receive_auth1():
    # desencriptar o ciphertext recebido em auth1
    cipherText = MANAGER_SOCKET.recv(MESSAGE_SIZE)
    plainText = Security.aesDecrypt(cipherText,SESSION_KEY)

    # desserializar o plaintext num objeto json
    message = json.loads(plainText)
    RECEIVED_MESSAGES.append(message)

    # testar se o campo 'type' da mensagem está correto
    if not message['type'] == 'AUTH1':
        raise Exception('Wrong message type "{}". Expected: "AUTH1".', message['type'])

    # verificar a assinatura do nonce enviado em auth0
    nonce = SENT_MESSAGES[-1]['nonce']
    signature = message['signature']

    if not Security.rsaVerify(nonce,signature,SERVER_PUBLIC_KEY):
        raise Exception('Invalid signature of the nonce sent in "AUTH0".')


def send_auth2():
    # produzir uma assinatura do nonce recebido pelo manager em auth1
    nonce = RECEIVED_MESSAGES[-1]['nonce']
    signature = Security.rsaSign(nonce,PRIVATE_KEY)

    # preparar a mensagem auth2 para ser enviada
    message = dict()
    message['type'] = 'AUTH2'
    message['signature'] = signature
    message['public_key'] = Security.rsaDumpKey(PUBLIC_KEY)

    # encriptar a mensagem auth2 com a chave de sessão
    plainText = json.dumps(message).encode()
    cipherText = Security.aesEncrypt(plainText,SESSION_KEY)

    # enviar a mensagem auth2
    MANAGER_SOCKET.sendall(cipherText)
    SENT_MESSAGES.append(message)


def commitment_stage():
    receive_comm0()
    send_comm1()
    receive_comm2()


def receive_comm0():
    cipherText = MANAGER_SOCKET.recv(MESSAGE_SIZE)
    plainText = Security.aesDecrypt(cipherText, SESSION_KEY)

    message = json.loads(plainText)
    RECEIVED_MESSAGES.append(message)

    if not message['type'] == 'COMM0':
        raise Exception('Wrong message type "{}". Expected: "COMM0".', message['type'])

    global M
    M = message['m']

    global N
    N = message['n']

    global PRICE
    PRICE = message['price']


def send_comm1():
    global CARDS
    CARDS = list()

    for _ in range(NR_CARDS):
        CARDS.append(random.sample(range(M),N))
    print('\nFase de comprometimento:\n')
    print("Carta(s) gerada(s): ", CARDS)

    global NONCE1
    global NONCE2
    NONCE1 = Security.nonce()
    NONCE2 = Security.nonce()

    global COMMIT
    COMMIT = Security.shaHash(NONCE1 + NONCE2 + str(CARDS))

    print("Comprometimento com as Cartas enviado!")

    message = dict()
    message['type'] = 'COMM1'
    message['nonce1'] = NONCE1
    message['commit'] = COMMIT

    plainText = json.dumps(message).encode()
    cipherText = Security.aesEncrypt(plainText,SESSION_KEY)

    MANAGER_SOCKET.sendall(cipherText)
    SENT_MESSAGES.append(message)


def receive_comm2():
    cipherText = MANAGER_SOCKET.recv(MESSAGE_SIZE)
    plainText = Security.aesDecrypt(cipherText, SESSION_KEY)

    message = json.loads(plainText)
    RECEIVED_MESSAGES.append(message)

    if not message['type'] == 'COMM2':
        raise Exception('Wrong message type "{}". Expected: "COMM2".', message['type'])

    global COMMITS
    COMMITS = message['commits']

    global NR_CLIENTS
    NR_CLIENTS = 0

    for commit in COMMITS:
        if commit:
            NR_CLIENTS += 1

    print("Comprometimentos de todos os Clients recebidos.")


def shuffling_stage():
    print('\nFase de baralhamento:\n')
    receive_shuf0()
    send_shuf1()
    receive_shuf2()


def receive_shuf0():
    cipherText = MANAGER_SOCKET.recv(MESSAGE_SIZE)
    plainText = Security.aesDecrypt(cipherText,SESSION_KEY)

    message = json.loads(plainText)
    RECEIVED_MESSAGES.append(message)

    if not message['type'] == 'SHUF0':
        raise Exception('Wrong message type "{}". Expected: "SHUF0".', message['type'])

    global DECK
    DECK = message['deck']

    print("Recebido baralho do Manager")


def send_shuf1():
    global SHUFFLING_KEY
    SHUFFLING_KEY = Security.aesKey()

    for i,n in enumerate(DECK):
        DECK[i] = Security.aesEncrypt(n.encode(),SHUFFLING_KEY).decode()

    random.shuffle(DECK)

    print("Enviado baralho baralhado e encriptado(número a número).")

    message = dict()
    message['type'] = 'SHUF1'
    message['deck'] = DECK

    plainText = json.dumps(message).encode()
    cipherText = Security.aesEncrypt(plainText,SESSION_KEY)

    MANAGER_SOCKET.sendall(cipherText)
    SENT_MESSAGES.append(message)


def receive_shuf2():
    cipherText = MANAGER_SOCKET.recv(MESSAGE_SIZE)
    plainText = Security.aesDecrypt(cipherText,SESSION_KEY)

    message = json.loads(plainText)
    RECEIVED_MESSAGES.append(message)

    if not message['type'] == 'SHUF2':
        raise Exception('Wrong message type "{}". Expected: "SHUF2".', message['type'])

    hashedDeck = Security.shaHash(str(message['deck']))

    if not Security.rsaVerify(hashedDeck,message['signature'],SERVER_PUBLIC_KEY):
        raise Exception('Invalid signature for final shuffled deck.')

    global DECK
    DECK = message['deck']

    print("Recebido baralho final baralhado e encriptado por todos os Clients e assinado pelo Manager.")


def revelation_stage():
    print('\nFase de revelação:\n')
    send_rev0()
    receive_rev1()
    send_rev2()


def send_rev0():
    message = dict()
    message['type'] = 'REV0'
    message['nonce2'] = NONCE2
    message['cards'] = CARDS
    message['shuffling_key'] = SHUFFLING_KEY

    plainText = json.dumps(message).encode()
    cipherText = Security.aesEncrypt(plainText, SESSION_KEY)

    MANAGER_SOCKET.sendall(cipherText)
    SENT_MESSAGES.append(message)

    print("Secrets enviados ao Manager.")


def receive_rev1():
    cipherText = MANAGER_SOCKET.recv(MESSAGE_SIZE)
    plainText = Security.aesDecrypt(cipherText, SESSION_KEY)

    message = json.loads(plainText)
    RECEIVED_MESSAGES.append(message)

    if not message['type'] == 'REV1':
        raise Exception('Wrong message type "{}". Expected: "REV1".', message['type'])

    global WINNERS
    WINNERS = message['winners']

    global SHUFFLING_KEYS
    SHUFFLING_KEYS = message['shuffling_keys']

    global SECRETS
    SECRETS = message['secrets']

    print("Recebidos secrets de todos os Clients.")


def send_rev2():
    # checka os bit commitments para todos os clients
    for name in COMMITS:
        commit = COMMITS[name]
        secret = SECRETS[name]

        commitHash = Security.shaHash(
            commit['nonce1'] +
            secret['nonce2'] +
            str(secret['cards'])
        )

        print("Comprometimento com as cartas dos Client", name, "verificado.")

        if not commitHash == commit['commit']:
            raise Exception('Invalid bit commitment from client "{}".'.format(name))

    # desencripta o baralho
    for key in SHUFFLING_KEYS:
        for i,n in enumerate(DECK):
            DECK[i] = Security.aesDecrypt(n.encode(),key).decode()

    print('Baralho baralhado e desencriptado com as shuffling keys de todos os Clients: {}'.format(DECK))

    # calcula os vencedores
    scores = list()

    for name in SECRETS:
        secret = SECRETS[name]
        for card in secret['cards']:
            card = set(card)
            for score,n in enumerate(DECK):
                card.discard(int(n))
                if len(card) == 0:
                    scores.append((score,name))
                    break

    scores.sort(reverse=True)

    # obter a lista dos vencedores (geralmente é só 1)
    winners = list()
    maxScore = scores[-1][0]

    while len(scores) > 0:
        score, client = scores.pop()
        if score == maxScore:
            winners.append(client)

    global NR_WINNERS
    NR_WINNERS = 0

    for winner in winners:
        if winner:
            NR_WINNERS += 1

    message = dict()
    message['type'] = 'REV2'
    message['winners'] = winners

    plainText = json.dumps(message).encode()
    cipherText = Security.aesEncrypt(plainText,SESSION_KEY)

    MANAGER_SOCKET.sendall(cipherText)
    SENT_MESSAGES.append(message)

    print('Vencedores:',winners)


def accounting_stage():
    print('\nFase de contabilidade:\n')
    receive_acc0()


def receive_acc0():
    cipherText = MANAGER_SOCKET.recv(MESSAGE_SIZE)
    plainText = Security.aesDecrypt(cipherText, SESSION_KEY)

    message = json.loads(plainText)
    RECEIVED_MESSAGES.append(message)

    if not message['type'] == 'ACC0':
        raise Exception('Wrong message type "{}". Expected: "ACC0".', message['type'])

    receipt = (NR_CLIENTS*PRICE)/NR_WINNERS

    finalreceipt = b64encode(str(receipt).encode()).decode()

    signature = message['signature']

    if not Security.rsaVerify(finalreceipt, signature, SERVER_PUBLIC_KEY):
        raise Exception('Invalid signature of the nonce sent in "ACC0".')

    global RECEIPT
    RECEIPT = receipt

    print("Eu sou o vencedor e tenho um recibo assinado pelo Manager!")


if __name__ == '__main__':

    if not len(sys.argv) == 3:
        print('Usage: python Client.py <name> <nr_cards>')
        sys.exit()

    ID = sys.argv[1]
    NR_CARDS = int(sys.argv[2])

    HOST, PORT = '127.0.0.1', 8080
    MESSAGE_SIZE = 1024 ** 2

    PUBLIC_KEY, PRIVATE_KEY = Security.rsaKeyPair()
    SERVER_PUBLIC_KEY = Security.rsaReadPublicKey('public.pem')
    SESSION_KEY = Security.aesKey()

    SENT_MESSAGES = list()
    RECEIVED_MESSAGES = list()

    MANAGER_SOCKET = socket.socket()
    MANAGER_SOCKET.connect((HOST,PORT))

    authentication_stage()
    commitment_stage()
    shuffling_stage()
    revelation_stage()
    accounting_stage()