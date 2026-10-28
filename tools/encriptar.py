#!/usr/bin/env python3
"""Gere o acesso encriptado à coleção do RB Market Check.

  python3 tools/encriptar.py adicionar RBMC1.xxxxx      # acrescenta uma pessoa (código da página registo.html)
  python3 tools/encriptar.py remover "Nome"             # retira o acesso a uma pessoa
  python3 tools/encriptar.py listar
  python3 tools/encriptar.py publicar colecao.json      # encripta a coleção para todas as pessoas

A coleção em claro NUNCA vai para o repositório: só data/cofre.json (encriptado) e
data/acesso.json (nomes + chaves públicas + chaves privadas encriptadas com a palavra-passe de cada um).
Cada publicação usa uma chave nova, por isso quem for removido deixa de abrir as versões seguintes.
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
    print('Removidos:', antes - len(a['pessoas']), '— faltam', len(a['pessoas']), '(publica de novo para mudar a chave)')


def publicar(caminho):
    a = ler_acesso()
    if not a['pessoas']:
        sys.exit('Ainda não há ninguém com acesso.')
    dados = open(caminho, 'rb').read()
    chave = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    cofre = {'v': 1, 'iv': b64(iv), 'dados': b64(AESGCM(chave).encrypt(iv, dados, None)), 'chaves': {}}
    for p in a['pessoas']:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64(p['pub']))
        eph = ec.generate_private_key(ec.SECP256R1())
        seg = eph.exchange(ec.ECDH(), pub)
        kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=b'rbmc-salt-v1', info=b'rbmc-v1').derive(seg)
        wiv = os.urandom(12)
        cofre['chaves'][p['pub']] = {
            'eph': b64(eph.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)),
            'iv': b64(wiv), 'k': b64(AESGCM(kek).encrypt(wiv, chave, None))}
    gravar(COFRE, cofre)
    print('Cofre publicado para', len(a['pessoas']), 'pessoa(s).')


if __name__ == '__main__':
    acao = sys.argv[1] if len(sys.argv) > 1 else ''
    if acao == 'adicionar': adicionar(sys.argv[2].strip())
    elif acao == 'remover': remover(sys.argv[2])
    elif acao == 'listar': print('\n'.join(p['nome'] for p in ler_acesso()['pessoas']) or '(ninguém)')
    elif acao == 'publicar': publicar(sys.argv[2])
    else: print(__doc__)
