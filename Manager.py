from base64 import b64encode

import Security
import socket
import threading
import sys
import json
import random
import os


def authentication_stage():
    global AUTH
    AUTH = True

    print('Fase de autenticação:\n')

    threading.Thread(target=listener).start()

    input('Pressione <ENTER> para começar o jogo ...\n')
    AUTH = False


def listener():
    # criar a própria socket
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    # associar a socket ao próprio (ip,port)
    sock.bind((HOST, PORT))

    # abrir a socket para começar a receber mensagens
    sock.listen(0)

    print('À espera que cheguem mensagens...')

    while AUTH:
        # esperar que chegue uma nova mensagem
        conn, addr = sock.accept()


        client = dict()
        client['socket'] = conn
        CLIENTS[addr] = client

        # enviar mensagem para o handler
        threading.Thread(
            target=auth_thread,
            args=(client,)
        ).start()


def auth_thread(client):
    receive_auth0(client),
    send_auth1(client),
    receive_auth2(client)
    MUTEX.acquire()
    print('Cliente "{}" autenticado com sucesso.'.format(client['id']))
    MUTEX.release()


def receive_auth0(client):
    # desencripta a mensagem com a sua chave privada
    cipherText = client['socket'].recv(MESSAGE_SIZE)
    plainText = Security.rsaDecrypt(cipherText, PRIVATE_KEY)

    # deserializar a mensagem no objecto json
    message = json.loads(plainText)

    # verificar se o tipo da mensagem é correcto
    if not message['type'] == 'AUTH0':
        raise Exception('Wrong message type "{}". Expected: "AUTH0".', message['type'])

    # guardar os dados da sessão do cliente em memória
    client['id'] = message['id']
    client['hashed_public_key'] = message['hashed_public_key']
    client['nonce'] = message['nonce']
    client['session_key'] = message['session_key']


def send_auth1(client):
    # produzir uma assinatura do nonce recebido em auth0
    signature = Security.rsaSign(client['nonce'], PRIVATE_KEY)

    # gerar um novo nonce para ser enviado
    client['nonce'] = Security.nonce()

    # preparar a mensagem auth1 a ser enviada
    message = dict()
    message['type'] = 'AUTH1'
    message['signature'] = signature
    message['nonce'] = client['nonce']

    # encriptar a mensagem com a chave de sessão
    plainText = json.dumps(message).encode()
    cipherText = Security.aesEncrypt(plainText, client['session_key'])

    # enviar a mensagem para o client
    client['socket'].sendall(cipherText)


def receive_auth2(client):
    # desencriptar a mensagem usando a session key do client
    cipherText = client['socket'].recv(MESSAGE_SIZE)
    plainText = Security.aesDecrypt(cipherText, client['session_key'])

    # deserializar a mensagem num objecto json
    message = json.loads(plainText)

    # testar se o campo 'type' está correto
    if not message['type'] == 'AUTH2':
        raise Exception('Wrong message type "{}". Expected: "AUTH2".', message['type'])

    signature = message['signature']
    publicKey = message['public_key']

    if not Security.shaHash(publicKey) == client['hashed_public_key']:
        raise Exception('The hash received in "AUTH0" does not match the calculated hash.')

    client['public_key'] = Security.rsaLoadKey(publicKey)

    if not Security.rsaVerify(client['nonce'], signature, client['public_key']):
        raise Exception('Invalid signature of the nonce sent in "AUTH1"')

    client.pop('hashed_public_key')
    client.pop('nonce')


def commitment_stage():
    print('Fase de comprometimento:\n')

    threads = list()

    for client in CLIENTS.values():
        thread = threading.Thread(
            target=lambda c: (
                send_comm0(c),
                receive_comm1(c)
            ),
            args=(client,)
        )
        threads.append(thread)

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    global COMMITS
    COMMITS = dict()

    for client in CLIENTS.values():
        commit = dict()
        commit['commit'] = client['commit']
        commit['nonce1'] = client['nonce1']
        COMMITS[client['id']] = commit

    for client in CLIENTS.values():
        send_comm2(client)


def send_comm0(client):
    message = dict()
    message['type'] = 'COMM0'
    message['m'] = M
    message['n'] = N
    message['price'] = PRICE

    plainText = json.dumps(message).encode()
    cipherText = Security.aesEncrypt(plainText, client['session_key'])

    client['socket'].sendall(cipherText)


def receive_comm1(client):
    cipherText = client['socket'].recv(MESSAGE_SIZE)
    plainText = Security.aesDecrypt(cipherText, client['session_key'])

    message = json.loads(plainText)

    if not message['type'] == 'COMM1':
        raise Exception('Wrong message type "{}". Expected: "COMM1".', message['type'])

    client['commit'] = message['commit']
    client['nonce1'] = message['nonce1']

    print('Recebido Compremetimento do Cliente "{}".'.format(client['id']))


def send_comm2(client):
    message = dict()
    message['type'] = 'COMM2'
    message['commits'] = COMMITS

    plainText = json.dumps(message).encode()
    cipherText = Security.aesEncrypt(plainText, client['session_key'])

    client['socket'].sendall(cipherText)

    print('Comprometimentos de todos os Clients enviados para Client "{}".'.format(client['id']))


def shuffling_stage():
    print('\nFase de baralhamento:\n')

    global DECK
    DECK = [str(num) for num in list(range(M))]

    print("Baralho criado: {}".format(DECK))

    global SHUFFLING_SEQUENCE
    SHUFFLING_SEQUENCE = list(CLIENTS.keys())
    random.shuffle(SHUFFLING_SEQUENCE)

    for name in SHUFFLING_SEQUENCE:
        client = CLIENTS[name]
        send_shuf0(client)
        receive_shuf1(client)

    global HASHED_DECK
    HASHED_DECK = Security.shaHash(str(DECK))

    global SIGNATURE
    SIGNATURE = Security.rsaSign(HASHED_DECK, PRIVATE_KEY)

    for client in CLIENTS.values():
        send_shuf2(client)


def send_shuf0(client):
    message = dict()
    message['type'] = 'SHUF0'
    message['deck'] = DECK

    plainText = json.dumps(message).encode()
    cipherText = Security.aesEncrypt(plainText, client['session_key'])

    client['socket'].sendall(cipherText)

    print('Baralho enviado para Client "{}".'.format(client['id']))


def receive_shuf1(client):
    cipherText = client['socket'].recv(MESSAGE_SIZE)
    plainText = Security.aesDecrypt(cipherText, client['session_key'])

    message = json.loads(plainText)

    if not message['type'] == 'SHUF1':
        raise Exception('Wrong message type "{}". Expected: "SHUF1".', message['type'])

    global DECK
    DECK = message['deck']

    print('Recebido baralho baralhado e encriptado por Client {}.'.format(client['id']))


def send_shuf2(client):
    message = dict()
    message['type'] = 'SHUF2'
    message['deck'] = DECK
    message['signature'] = SIGNATURE

    plainText = json.dumps(message).encode()
    cipherText = Security.aesEncrypt(plainText, client['session_key'])

    client['socket'].sendall(cipherText)

    print('Baralho baralhado e encriptado por todos os Clients, assinado e enviado para Client "{}".'.format(client['id']))


def revelation_stage():
    print('\nFase de revelação:\n')

    # recebe os segredos de todos os clientes
    for client in CLIENTS.values():
        receive_rev0(client)

    global SECRETS
    SECRETS = dict()

    for client in CLIENTS.values():

        # calcular o bit commitment do cliente
        commitment = Security.shaHash(
            client['nonce1'] +
            client['nonce2'] +
            str(client['cards'])
        )
        # comparar o commit calculado agora com o commit recebido em comm1
        if not client['commit'] == commitment:
            raise Exception('Invalid bit commitment from client "{}".'.format(client['id']))

        print("Comprometimento com as cartas do Client {}".format(client['id']), "verificado.")

        # adicionar o segredo do cliente à lista de segredos a ser enviada
        secret = dict()
        secret['nonce2'] = client['nonce2']
        secret['cards'] = client['cards']
        SECRETS[client['id']] = secret

    global SHUFFLING_KEYS
    SHUFFLING_KEYS = list()

    for name in reversed(SHUFFLING_SEQUENCE):
        client = CLIENTS[name]
        SHUFFLING_KEYS.append(client['shuffling_key'])

    for key in SHUFFLING_KEYS:
        for i, n in enumerate(DECK):
            DECK[i] = Security.aesDecrypt(n.encode(), key).decode()

    print('Baralho baralhado e desencriptado com as shuffling keys de todos os Clients: {}'.format(DECK))

    # calcular pontuação dos jogadores (quão rápido acabaram os seus cartões)
    scores = list()
    for client in CLIENTS.values():
        for card in client['cards']:
            card = set(card)
            for score, n in enumerate(DECK):
                card.discard(int(n))
                if len(card) == 0:
                    scores.append((score, client['id']))
                    break
    scores.sort(reverse=True)

    # obter a lista dos vencedores (geralmente é só 1)
    global WINNERS
    WINNERS = list()
    maxScore = scores[-1][0]

    while len(scores) > 0:
        score, client = scores.pop()
        if score == maxScore:
            WINNERS.append(client)

    print('Vencedores:', WINNERS)

    # enviar segredos e shuffling keys a todos os clientes
    revThreads = list()
    for client in CLIENTS.values():
        revThreads.append(
            threading.Thread(
                target=rev_thread,
                args=(client,)
            )
        )

    for thread in revThreads:
        thread.start()

    for thread in revThreads:
        thread.join()


def rev_thread(client):
    send_rev1(client)
    receive_rev2(client)


def receive_rev0(client):
    cipherText = client['socket'].recv(MESSAGE_SIZE)
    plainText = Security.aesDecrypt(cipherText, client['session_key'])

    message = json.loads(plainText)

    if not message['type'] == 'REV0':
        raise Exception('Wrong message type "{}". Expected: "REV0".', message['type'])

    client['nonce2'] = message['nonce2']
    client['cards'] = message['cards']
    client['shuffling_key'] = message['shuffling_key']

    print('Recebidos os secrets do Client "{}".'.format(client['id']))
    print('Cartas do Client {}'.format(client['id']), ':{}'.format(client['cards']))


def send_rev1(client):
    message = dict()
    message['type'] = 'REV1'
    message['secrets'] = SECRETS
    message['winners'] = WINNERS
    message['shuffling_keys'] = SHUFFLING_KEYS

    plainText = json.dumps(message).encode()
    cipherText = Security.aesEncrypt(plainText, client['session_key'])

    client['socket'].sendall(cipherText)

    print('Secrets de todos os Clients enviado para Client "{}".'.format(client['id']))


def receive_rev2(client):
    cipherText = client['socket'].recv(MESSAGE_SIZE)
    plainText = Security.aesDecrypt(cipherText, client['session_key'])

    message = json.loads(plainText)

    if not message['type'] == 'REV2':
        raise Exception('Wrong message type "{}". Expected: "REV2".', message['type'])

    client['winners'] = message['winners']

    MUTEX.acquire()
    print('Vencedores do cliente "{}":'.format(client['id']), client['winners'])
    MUTEX.release()


def accounting_stage():
    print('\nFase de contabilidade:\n')

    global I
    I = 0
    global NR_WINNERS
    NR_WINNERS = 0

    for client in CLIENTS.values():
        if client['id']:
            I += 1

    for winner in WINNERS:
        if winner:
            NR_WINNERS += 1

    for client in CLIENTS.values():
        for winner in WINNERS:
            if winner in client['winners']:
                if client['id'] == winner:
                    send_acc0(client)


def send_acc0(client):
    aux = (I * PRICE) / NR_WINNERS

    receipt = b64encode(str(aux).encode()).decode()

    signature = Security.rsaSign(receipt, PRIVATE_KEY)

    message = dict()
    message['type'] = 'ACC0'
    message['signature'] = signature

    plainText = json.dumps(message).encode()
    cipherText = Security.aesEncrypt(plainText, client['session_key'])

    client['socket'].sendall(cipherText)

    print('Recibo enviado com o valor de {}'.format(aux), 'euros para o Client vencedor "{}".'.format(client['id']))


if __name__ == '__main__':

    if not len(sys.argv) == 4:
        print('Usage: python Manager.py <m> <n> <price>')
        sys.exit()

    HOST, PORT = '127.0.0.1', 8080
    MESSAGE_SIZE = 1024 ** 2
    M, N = int(sys.argv[1]), int(sys.argv[2])
    PRICE = int(sys.argv[3])

    PUBLIC_KEY = Security.rsaReadPublicKey('public.pem')
    PRIVATE_KEY = Security.rsaReadPrivateKey('private.pem')

    CLIENTS = dict()
    MUTEX = threading.Lock()

    authentication_stage()
    commitment_stage()
    shuffling_stage()
    revelation_stage()
    accounting_stage()