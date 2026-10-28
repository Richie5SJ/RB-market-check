#!/usr/bin/env python3
"""Gere o acesso encriptado à coleção do RB Market Check.

  python3 tools/encriptar.py adicionar RBMC1.xxxxx      # acrescenta uma pessoa (código da página registo.html)
  python3 tools/encriptar.py remover "Nome"             # retira o acesso a uma pessoa
  python3 tools/encriptar.py listar
  python3 tools/encriptar.py publicar "Nome" colecao.json  # encripta a coleção DESSA pessoa, só para ela

A coleção em claro NUNCA vai para o repositório: só data/cofre.json (encriptado) e
data/acesso.json (nomes + chaves públicas + chaves privadas encriptadas com a palavra-passe de cada um).
Cada pessoa tem a sua própria coleção, encriptada só para ela, com uma chave nova a cada publicação.
"""
import base64, json, os, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACESSO = os.path.join(RAIZ, 'data', 'acesso.json')
COFRE = os.path.join(RAIZ, 'data', 'cofre.json')
b64 = lambda b: base64.b64encode(b).decode()
unb64 = base64.b64decode


def ler_acesso():
    if os.path.exists(ACESSO):
        return json.load(open(ACESSO))
    return {'pessoas': []}


def gravar(path, obj):
    with open(path, 'w') as f:
        json.dump(obj, f, ensure_ascii=False, separators=(',', ':'))


def adicionar(codigo):
    if not codigo.startswith('RBMC1.'):
        sys.exit('Código inválido.')
    c = json.loads(base64.b64decode(codigo[6:]).decode())
    for k in ('nome', 'salt', 'iv', 'priv', 'pub'):
        if not isinstance(c.get(k), str):
            sys.exit('Código incompleto.')
    pub = unb64(c['pub'])
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)  # valida a chave
    a = ler_acesso()
    a['pessoas'] = [p for p in a['pessoas'] if p['pub'] != c['pub']]
    a['pessoas'].append({k: c[k] for k in ('nome', 'salt', 'iv', 'priv', 'pub')})
    gravar(ACESSO, a)
    print('Adicionado:', c['nome'], '— total', len(a['pessoas']))


def remover(nome):
    a = ler_acesso()
    antes = len(a['pessoas'])
    a['pessoas'] = [p for p in a['pessoas'] if p['nome'] != nome]
    gravar(ACESSO, a)
    limpar()
    print('Removidos:', antes - len(a['pessoas']), '— faltam', len(a['pessoas']))


def publicar(nome, caminho):
    a = ler_acesso()
    pessoa = next((p for p in a['pessoas'] if p['nome'] == nome), None)
    if not pessoa:
        sys.exit('Essa pessoa não tem acesso: ' + nome)
    cofre = json.load(open(COFRE)) if os.path.exists(COFRE) else {}
    if cofre.get('v') != 2:
        cofre = {'v': 2, 'colecoes': {}}
    dados = open(caminho, 'rb').read()
    chave = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64(pessoa['pub']))
    eph = ec.generate_private_key(ec.SECP256R1())
    seg = eph.exchange(ec.ECDH(), pub)
    kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=b'rbmc-salt-v1', info=b'rbmc-v1').derive(seg)
    wiv = os.urandom(12)
    cofre['colecoes'][pessoa['pub']] = {
        'eph': b64(eph.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)),
        'iv': b64(wiv), 'k': b64(AESGCM(kek).encrypt(wiv, chave, None)),
        'div': b64(iv), 'dados': b64(AESGCM(chave).encrypt(iv, dados, None))}
    validos = {p['pub'] for p in a['pessoas']}
    cofre['colecoes'] = {k: v for k, v in cofre['colecoes'].items() if k in validos}
    gravar(COFRE, cofre)
    print('Coleção de', nome, 'publicada. Coleções no cofre:', len(cofre['colecoes']))


def limpar():
    a = ler_acesso()
    if os.path.exists(COFRE):
        cofre = json.load(open(COFRE))
        if cofre.get('v') == 2:
            validos = {p['pub'] for p in a['pessoas']}
            cofre['colecoes'] = {k: v for k, v in cofre['colecoes'].items() if k in validos}
            gravar(COFRE, cofre)


if __name__ == '__main__':
    acao = sys.argv[1] if len(sys.argv) > 1 else ''
    if acao == 'adicionar': adicionar(sys.argv[2].strip())
    elif acao == 'remover': remover(sys.argv[2])
    elif acao == 'listar': print('\n'.join(p['nome'] for p in ler_acesso()['pessoas']) or '(ninguém)')
    elif acao == 'publicar': publicar(sys.argv[2], sys.argv[3])
    else: print(__doc__)
