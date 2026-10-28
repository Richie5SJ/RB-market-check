// Encriptação da coleção — tudo corre no navegador, nada é enviado para lado nenhum.
// Cada pessoa tem um par de chaves ECDH P-256. A chave privada fica guardada encriptada
// com a palavra-passe dessa pessoa (PBKDF2 → AES-GCM). A coleção é encriptada com uma
// chave nova a cada atualização, e essa chave é embrulhada para a chave pública de cada pessoa.
window.RBC = (function () {
  const te = new TextEncoder(), td = new TextDecoder();
  const ITER = 600000;
  const HKDF_SALT = te.encode('rbmc-salt-v1'), HKDF_INFO = te.encode('rbmc-v1');
  const b64 = (buf) => { const a = new Uint8Array(buf); let s = ''; for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000)); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function chaveDaPasse(passe, salt) {
    const base = await crypto.subtle.importKey('raw', te.encode(passe), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  // Registo: devolve o código para enviar (sem a palavra-passe).
  async function registar(nome, passe) {
    const par = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const priv = await crypto.subtle.exportKey('pkcs8', par.privateKey);
    const pub = await crypto.subtle.exportKey('raw', par.publicKey);
    const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    const k = await chaveDaPasse(passe, salt);
    const privEnc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, priv);
    const codigo = { v: 1, nome, salt: b64(salt), iv: b64(iv), priv: b64(privEnc), pub: b64(pub) };
    return 'RBMC1.' + btoa(unescape(encodeURIComponent(JSON.stringify(codigo))));
  }

  // Desbloqueio: tenta a palavra-passe em cada entrada da lista de acesso.
  async function abrir(passe, acesso, cofre) {
    for (const e of acesso.pessoas || []) {
      if (!cofre.chaves || !cofre.chaves[e.pub]) continue;
      let privRaw;
      try {
        const k = await chaveDaPasse(passe, unb64(e.salt));
        privRaw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(e.iv) }, k, unb64(e.priv));
      } catch (_) { continue; }
      const priv = await crypto.subtle.importKey('pkcs8', privRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
      const eph = await crypto.subtle.importKey('raw', unb64(cofre.chaves[e.pub].eph), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
      const seg = await crypto.subtle.deriveBits({ name: 'ECDH', public: eph }, priv, 256);
      const hk = await crypto.subtle.importKey('raw', seg, 'HKDF', false, ['deriveKey']);
      const kek = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: HKDF_INFO }, hk, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
      const w = cofre.chaves[e.pub];
      const dk = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(w.iv) }, kek, unb64(w.k));
      const chave = await crypto.subtle.importKey('raw', dk, 'AES-GCM', false, ['decrypt']);
      const dados = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(cofre.iv) }, chave, unb64(cofre.dados));
      return { nome: e.nome, dados: JSON.parse(td.decode(dados)) };
    }
    return null;
  }
  return { registar, abrir };
})();
