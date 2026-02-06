/* ============================================================
 *  QUANTUM VAULT — Production-Grade Post-Quantum Encryption
 *  main.js  |  All client-side cryptographic logic
 *
 *  Algorithms
 *    KEM  : X-Wing  (ML-KEM-768 + X25519, IETF Draft)
 *    DSA  : ML-DSA-65  (FIPS 204, NIST Category 3)
 *    AEAD : AES-256-GCM  (Web Crypto API)
 *    KDF  : HKDF-SHA256  (RFC 5869)
 *
 *  Dependencies
 *    @noble/post-quantum 0.5.2  (esm.sh CDN)
 * ============================================================ */

import { XWing } from 'https://esm.sh/@noble/post-quantum@0.5.2/hybrid.js';
import { ml_dsa65 } from 'https://esm.sh/@noble/post-quantum@0.5.2/ml-dsa.js';

/* ---- Expose to inline onclick handlers ---- */
window.XWing = XWing;
window.ml_dsa65 = ml_dsa65;

/* ---- State ---- */
let encFileData = null, encFileName = '';
let decFileText = null;
let encryptedPackage = null;
let decryptedBlob = null, decryptedName = '';

/* ---- Utilities ---- */
const $ = id => document.getElementById(id);
const toHex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const fromHex = h => new Uint8Array(h.match(/.{1,2}/g).map(x => parseInt(x, 16)));
const fmtBytes = b => b < 1024 ? b + ' B' : b < 1048576 ? (b/1024).toFixed(1) + ' KB' : (b/1048576).toFixed(2) + ' MB';

const toast = (msg, isError = false) => {
  const t = $('toast');
  t.textContent = msg;
  t.classList.toggle('error', isError);
  t.classList.add('visible');
  setTimeout(() => t.classList.remove('visible'), 4000);
};

/* ---- Crypto Helpers ---- */
async function sha256(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

async function hkdfDerive(sharedSecret, salt, info, keyLength = 32) {
  const keyMaterial = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt, info: new TextEncoder().encode(info) },
    keyMaterial,
    keyLength * 8
  );
  return new Uint8Array(derivedBits);
}

/* ---- Tab Navigation ---- */
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    $(`panel-${tab.dataset.tab}`).classList.add('active');
  });
});

/* ---- Key Generation: X-Wing ---- */
window.genXWing = async () => {
  const btn = $('xwing-btn');
  btn.disabled = true;
  btn.textContent = 'Generating...';
  try {
    const t0 = performance.now();
    const { secretKey, publicKey } = XWing.keygen();
    const ms = (performance.now() - t0).toFixed(1);
    $('xwing-pk').textContent = toHex(publicKey);
    $('xwing-sk').textContent = toHex(secretKey);
    $('xwing-pk-sz').textContent = `(${publicKey.length} bytes)`;
    $('xwing-sk-sz').textContent = `(${secretKey.length} bytes)`;
    $('xwing-stats').innerHTML = `
      <div class="stat"><div class="stat-val">${ms}ms</div><div class="stat-label">Keygen</div></div>
      <div class="stat"><div class="stat-val">${publicKey.length}</div><div class="stat-label">PK bytes</div></div>
      <div class="stat"><div class="stat-val">${secretKey.length}</div><div class="stat-label">SK bytes</div></div>
      <div class="stat"><div class="stat-val">X-Wing</div><div class="stat-label">Algorithm</div></div>
    `;
    $('xwing-keys').classList.add('visible');
    toast(`X-Wing keypair generated in ${ms}ms`);
  } catch (e) { toast('Error: ' + e.message, true); }
  btn.disabled = false;
  btn.textContent = 'Generate X-Wing Keypair';
};

/* ---- Key Generation: ML-DSA-65 ---- */
window.genDSA = async () => {
  const btn = $('dsa-btn');
  btn.disabled = true;
  btn.textContent = 'Generating...';
  try {
    const t0 = performance.now();
    const { secretKey, publicKey } = ml_dsa65.keygen();
    const ms = (performance.now() - t0).toFixed(1);
    $('dsa-pk').textContent = toHex(publicKey);
    $('dsa-sk').textContent = toHex(secretKey);
    $('dsa-pk-sz').textContent = `(${publicKey.length} bytes)`;
    $('dsa-sk-sz').textContent = `(${secretKey.length} bytes)`;
    $('dsa-stats').innerHTML = `
      <div class="stat"><div class="stat-val">${ms}ms</div><div class="stat-label">Keygen</div></div>
      <div class="stat"><div class="stat-val">${publicKey.length}</div><div class="stat-label">PK bytes</div></div>
      <div class="stat"><div class="stat-val">${secretKey.length}</div><div class="stat-label">SK bytes</div></div>
      <div class="stat"><div class="stat-val">ML-DSA-65</div><div class="stat-label">Algorithm</div></div>
    `;
    $('dsa-keys').classList.add('visible');
    toast(`ML-DSA-65 keypair generated in ${ms}ms`);
  } catch (e) { toast('Error: ' + e.message, true); }
  btn.disabled = false;
  btn.textContent = 'Generate ML-DSA-65 Keypair';
};

/* ---- Encrypt: File Handling ---- */
$('enc-file').addEventListener('change', async function() {
  if (!this.files.length) return;
  const f = this.files[0];
  encFileName = f.name;
  encFileData = new Uint8Array(await f.arrayBuffer());
  $('enc-fname').textContent = f.name;
  $('enc-fsize').textContent = fmtBytes(f.size);
  $('enc-finfo').classList.add('visible');
  $('enc-drop').style.display = 'none';
  checkEncBtn();
});

window.clearEncFile = () => {
  encFileData = null; encFileName = '';
  $('enc-finfo').classList.remove('visible');
  $('enc-drop').style.display = '';
  $('enc-file').value = '';
  checkEncBtn();
};

$('enc-pk').addEventListener('input', checkEncBtn);
function checkEncBtn() {
  const hasFile = encFileData !== null;
  const hasKey = $('enc-pk').value.trim().length === 2432;
  $('enc-btn').disabled = !(hasFile && hasKey);
}

/* ---- Decrypt: File Handling ---- */
$('dec-file').addEventListener('change', async function() {
  if (!this.files.length) return;
  const f = this.files[0];
  decFileText = await f.text();
  $('dec-fname').textContent = f.name;
  $('dec-fsize').textContent = fmtBytes(f.size);
  $('dec-finfo').classList.add('visible');
  $('dec-drop').style.display = 'none';
  checkDecBtn();
});

window.clearDecFile = () => {
  decFileText = null;
  $('dec-finfo').classList.remove('visible');
  $('dec-drop').style.display = '';
  $('dec-file').value = '';
  checkDecBtn();
};

$('dec-sk').addEventListener('input', checkDecBtn);
function checkDecBtn() {
  const hasFile = decFileText !== null;
  const hasKey = $('dec-sk').value.trim().length === 64;
  $('dec-btn').disabled = !(hasFile && hasKey);
}

/* ---- Encrypt File ---- */
window.encryptFile = async () => {
  const prog = $('enc-prog'), result = $('enc-result');
  prog.classList.add('visible');
  result.classList.remove('visible');
  const setProgress = (pct) => { $('enc-fill').style.width = pct + '%'; $('enc-pct').textContent = pct + '%'; };

  try {
    setProgress(10);
    const recipientPk = fromHex($('enc-pk').value.trim());
    if (recipientPk.length !== 1216) throw new Error('Invalid X-Wing public key (must be 1216 bytes)');
    setProgress(20);
    const { sharedSecret, cipherText } = XWing.encapsulate(recipientPk);
    setProgress(40);
    const hkdfSalt = crypto.getRandomValues(new Uint8Array(32));
    const aesKeyBytes = await hkdfDerive(sharedSecret, hkdfSalt, 'QuantumVault-v1-AES256GCM', 32);
    setProgress(50);
    const aesKey = await crypto.subtle.importKey('raw', aesKeyBytes, 'AES-GCM', false, ['encrypt']);
    const aesNonce = crypto.getRandomValues(new Uint8Array(12));
    setProgress(60);
    const plaintextHash = await sha256(encFileData);
    setProgress(70);
    const aesCiphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: aesNonce }, aesKey, encFileData);
    setProgress(90);
    encryptedPackage = {
      version: '2.0',
      algorithm: 'X-Wing+HKDF-SHA256+AES-256-GCM',
      kem: { name: 'X-Wing', ciphertext: toHex(cipherText) },
      kdf: { name: 'HKDF-SHA256', salt: toHex(hkdfSalt), info: 'QuantumVault-v1-AES256GCM' },
      aead: { name: 'AES-256-GCM', nonce: toHex(aesNonce), ciphertext: toHex(new Uint8Array(aesCiphertext)) },
      metadata: { originalName: encFileName, originalSize: encFileData.length, plaintextHash: toHex(plaintextHash), encryptedAt: new Date().toISOString() }
    };
    setProgress(100);
    setTimeout(() => { prog.classList.remove('visible'); result.classList.add('visible'); toast('File encrypted with X-Wing hybrid KEM'); }, 200);
  } catch (e) { prog.classList.remove('visible'); toast('Encryption error: ' + e.message, true); }
};

/* ---- Decrypt File ---- */
window.decryptFile = async () => {
  const prog = $('dec-prog'), result = $('dec-result');
  prog.classList.add('visible');
  result.classList.remove('visible', 'error');
  const setProgress = (pct) => { $('dec-fill').style.width = pct + '%'; $('dec-pct').textContent = pct + '%'; };

  try {
    setProgress(10);
    const pkg = JSON.parse(decFileText);
    if (pkg.version !== '2.0' || pkg.algorithm !== 'X-Wing+HKDF-SHA256+AES-256-GCM') throw new Error('Unsupported file format');
    setProgress(20);
    const secretKey = fromHex($('dec-sk').value.trim());
    if (secretKey.length !== 32) throw new Error('Invalid X-Wing secret key (must be 32 bytes)');
    const kemCiphertext = fromHex(pkg.kem.ciphertext);
    setProgress(30);
    const sharedSecret = XWing.decapsulate(kemCiphertext, secretKey);
    setProgress(50);
    const hkdfSalt = fromHex(pkg.kdf.salt);
    const aesKeyBytes = await hkdfDerive(sharedSecret, hkdfSalt, pkg.kdf.info, 32);
    const aesKey = await crypto.subtle.importKey('raw', aesKeyBytes, 'AES-GCM', false, ['decrypt']);
    setProgress(60);
    const aesNonce = fromHex(pkg.aead.nonce);
    const aesCiphertext = fromHex(pkg.aead.ciphertext);
    setProgress(70);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: aesNonce }, aesKey, aesCiphertext);
    setProgress(85);
    if (pkg.metadata.plaintextHash) {
      const computedHash = await sha256(new Uint8Array(plaintext));
      if (toHex(computedHash) !== pkg.metadata.plaintextHash) throw new Error('Integrity check failed');
    }
    setProgress(100);
    decryptedBlob = new Blob([plaintext]);
    decryptedName = pkg.metadata.originalName || 'decrypted_file';
    setTimeout(() => { prog.classList.remove('visible'); result.classList.add('visible'); $('dec-icon').textContent = '\u2713'; $('dec-title').textContent = 'Decrypted & Verified'; toast('File decrypted and integrity verified'); }, 200);
  } catch (e) { prog.classList.remove('visible'); result.classList.add('visible', 'error'); $('dec-icon').textContent = '\u2715'; $('dec-title').textContent = 'Decryption Failed'; toast('Error: ' + e.message, true); }
};

/* ---- Download Helpers ---- */
window.downloadEnc = () => {
  const blob = new Blob([JSON.stringify(encryptedPackage, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = encFileName + '.pqenc';
  a.click();
  URL.revokeObjectURL(a.href);
};

window.downloadDec = () => {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(decryptedBlob);
  a.download = decryptedName;
  a.click();
  URL.revokeObjectURL(a.href);
};

/* ---- Sign Message ---- */
window.signMessage = async () => {
  const msg = $('sign-msg').value, skHex = $('sign-sk').value.trim();
  if (!msg) { toast('Enter a message to sign', true); return; }
  if (skHex.length !== 8064) { toast('Invalid ML-DSA-65 secret key (must be 4032 bytes)', true); return; }
  try {
    const secretKey = fromHex(skHex);
    const msgBytes = new TextEncoder().encode(msg);
    const t0 = performance.now();
    const signature = ml_dsa65.sign(secretKey, msgBytes);
    const ms = (performance.now() - t0).toFixed(1);
    $('sig-val').textContent = toHex(signature);
    $('sig-sz').textContent = `(${signature.length} bytes, ${ms}ms)`;
    $('sig-out').classList.add('visible');
    toast(`Signed with ML-DSA-65 in ${ms}ms`);
  } catch (e) { toast('Signing error: ' + e.message, true); }
};

/* ---- Verify Signature ---- */
window.verifyMessage = async () => {
  const msg = $('ver-msg').value, sigHex = $('ver-sig').value.trim(), pkHex = $('ver-pk').value.trim();
  if (!msg || !sigHex || !pkHex) { toast('Fill all fields', true); return; }
  if (pkHex.length !== 3904) { toast('Invalid ML-DSA-65 public key (must be 1952 bytes)', true); return; }
  const result = $('ver-result');
  result.classList.remove('visible', 'error');
  try {
    const publicKey = fromHex(pkHex), signature = fromHex(sigHex);
    const msgBytes = new TextEncoder().encode(msg);
    const t0 = performance.now();
    const valid = ml_dsa65.verify(publicKey, msgBytes, signature);
    const ms = (performance.now() - t0).toFixed(1);
    result.classList.add('visible');
    if (valid) { $('ver-icon').textContent = '\u2713'; $('ver-title').textContent = `Signature Valid (${ms}ms)`; toast('Signature verified!'); }
    else { result.classList.add('error'); $('ver-icon').textContent = '\u2715'; $('ver-title').textContent = 'Invalid Signature'; toast('Signature verification failed', true); }
  } catch (e) { result.classList.add('visible', 'error'); $('ver-icon').textContent = '\u2715'; $('ver-title').textContent = 'Verification Error'; toast('Error: ' + e.message, true); }
};

/* ---- Clipboard ---- */
window.copyEl = id => { navigator.clipboard.writeText($(id).textContent); toast('Copied to clipboard'); };

/* ---- Drag and Drop ---- */
['enc-drop', 'dec-drop'].forEach(id => {
  const zone = $(id);
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag'));
  zone.addEventListener('drop', e => { e.preventDefault(); zone.classList.remove('drag'); const input = $(id.replace('drop', 'file')); input.files = e.dataTransfer.files; input.dispatchEvent(new Event('change')); });
});

/* ---- Init Complete ---- */
$('loading').classList.add('hidden');
