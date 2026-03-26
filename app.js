const el = (id) => document.getElementById(id);

const algoSel = el("algo");
const keyInput = el("key");
const shiftInput = el("shift");
const inputArea = el("input");
const outputArea = el("output");
const hint = el("hint");
const alertBox = el("alert");
const shiftField = el("shiftField");
const keyField = el("keyField");

const modeButtons = [...document.querySelectorAll(".seg")];
let mode = "encrypt";

modeButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    modeButtons.forEach((b) => b.classList.remove("is-active"));
    btn.classList.add("is-active");
    mode = btn.dataset.mode;
    clearAlert();
    updateHint();
  });
});

algoSel.addEventListener("change", () => {
  clearAlert();
  updateHint();
});

document.getElementById("run").addEventListener("click", async () => {
  clearAlert();
  hint.textContent = "";
  try {
    const algo = algoSel.value;
    const text = inputArea.value;
    if (!text.trim()) throw new Error("Veuillez saisir un texte d'entrée.");

    let result = "";
    if (algo === "aes") {
      result = await runAES(text);
    } else if (algo === "cesar") {
      result = runCesar(text);
    } else if (algo === "vigenere") {
      result = runVigenere(text);
    } else if (algo === "sdes") {
      result = runSDES(text);
    }
    outputArea.value = result;
  } catch (err) {
    outputArea.value = "";
    showAlert(err.message || String(err));
  }
});

document.getElementById("swap").addEventListener("click", () => {
  const tmp = inputArea.value;
  inputArea.value = outputArea.value;
  outputArea.value = tmp;
});

const copyBtn = document.getElementById("copy");

copyBtn.addEventListener("click", async () => {
  if (!outputArea.value) return;
  try {
    await navigator.clipboard.writeText(outputArea.value);
    hint.textContent = "Sortie copiée dans le presse‑papier.";
    copyBtn.classList.add("copied");
    setTimeout(() => copyBtn.classList.remove("copied"), 180);
  } catch {
    showAlert("Copie impossible. Vérifie les permissions du navigateur.");
  }
});

function updateHint() {
  const algo = algoSel.value;
  keyField.style.display = algo === "cesar" ? "none" : "flex";
  shiftField.style.display = algo === "cesar" ? "flex" : "none";

  if (algo === "aes") {
    hint.textContent = "AES-GCM: sortie en Base64. Format: version(1) + salt(16) + iv(12) + ciphertext.";
  } else if (algo === "cesar") {
    hint.textContent = "César: décalage entre 0 et 25. Chiffre seulement A‑Z/a‑z.";
  } else if (algo === "vigenere") {
    hint.textContent = "Vigenère: clé alphabétique (lettres uniquement).";
  } else if (algo === "sdes") {
    hint.textContent = "S‑DES: clé libre, sortie en Base64. Déchiffrement attend du Base64.";
  }
}

updateHint();

function showAlert(message) {
  alertBox.textContent = message;
  alertBox.classList.add("is-visible");
}

function clearAlert() {
  alertBox.textContent = "";
  alertBox.classList.remove("is-visible");
}

// AES (WebCrypto)
async function runAES(text) {
  const password = keyInput.value.trim();
  if (!password) throw new Error("Ajoute un mot de passe pour AES.");

  if (mode === "encrypt") {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveAesKey(password, salt);
    const data = new TextEncoder().encode(text);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);

    const payload = packAesPayload(salt, iv, new Uint8Array(ct));
    return toBase64(payload);
  }

  // decrypt
  const bytes = fromBase64(text.trim(), "AES: entrée Base64 invalide.");
  const { salt, iv, ct } = unpackAesPayload(bytes);
  const key = await deriveAesKey(password, salt);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new TextDecoder().decode(pt);
}

async function deriveAesKey(password, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function toBase64(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

function fromBase64(str, errorMessage = "Entrée Base64 invalide.") {
  try {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    throw new Error(errorMessage);
  }
}

function packAesPayload(salt, iv, ct) {
  const version = 1;
  const out = new Uint8Array(1 + salt.length + iv.length + ct.length);
  out[0] = version;
  out.set(salt, 1);
  out.set(iv, 1 + salt.length);
  out.set(ct, 1 + salt.length + iv.length);
  return out;
}

function unpackAesPayload(bytes) {
  if (bytes.length < 1 + 16 + 12) {
    throw new Error("AES: entrée Base64 invalide (trop courte).");
  }
  const version = bytes[0];
  if (version !== 1) {
    throw new Error("AES: version de payload inconnue.");
  }
  const salt = bytes.slice(1, 17);
  const iv = bytes.slice(17, 29);
  const ct = bytes.slice(29);
  return { salt, iv, ct };
}

// Cesar
function runCesar(text) {
  const shift = Number(shiftInput.value) % 26;
  const dir = mode === "encrypt" ? shift : (26 - shift) % 26;
  return text.replace(/[A-Za-z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + dir) % 26) + base);
  });
}

// Vigenere
function runVigenere(text) {
  const key = keyInput.value.replace(/[^A-Za-z]/g, "").toLowerCase();
  if (!key) throw new Error("Vigenère: clé alphabétique requise.");
  let ki = 0;
  return text.replace(/[A-Za-z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    const k = key.charCodeAt(ki % key.length) - 97;
    ki++;
    const shift = mode === "encrypt" ? k : (26 - k) % 26;
    return String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
  });
}

// S-DES (pédagogique)
const P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6];
const P8 = [6, 3, 7, 4, 8, 5, 10, 9];
const IP = [2, 6, 3, 1, 4, 8, 5, 7];
const IP_INV = [4, 1, 3, 5, 7, 2, 8, 6];
const EP = [4, 1, 2, 3, 2, 3, 4, 1];
const P4 = [2, 4, 3, 1];
const S0 = [
  [1, 0, 3, 2],
  [3, 2, 1, 0],
  [0, 2, 1, 3],
  [3, 1, 3, 2],
];
const S1 = [
  [0, 1, 2, 3],
  [2, 0, 1, 3],
  [3, 0, 1, 0],
  [2, 1, 0, 3],
];

function runSDES(text) {
  const keyStr = keyInput.value.trim();
  if (!keyStr) {
    throw new Error("S‑DES: ajoute une clé.");
  }
  const keyBits = keyTo10Bits(keyStr);
  const { K1, K2 } = sdesKeygen(keyBits);

  if (mode === "encrypt") {
    const bytes = new TextEncoder().encode(text);
    const out = [];
    for (const b of bytes) {
      const enc = sdesEncryptByte(b, K1, K2);
      out.push(enc);
    }
    return toBase64(new Uint8Array(out));
  }

  const bytes = fromBase64(text.trim(), "S‑DES: entrée Base64 invalide.");
  const out = Array.from(bytes, (b) => sdesDecryptByte(b, K1, K2));
  return new TextDecoder().decode(new Uint8Array(out));
}

function sdesKeygen(key10) {
  const p10 = permute(key10, P10);
  let left = p10.slice(0, 5);
  let right = p10.slice(5);
  left = leftShift(left, 1);
  right = leftShift(right, 1);
  const K1 = permute(left.concat(right), P8);
  left = leftShift(left, 2);
  right = leftShift(right, 2);
  const K2 = permute(left.concat(right), P8);
  return { K1, K2 };
}

function sdesEncryptByte(byte, K1, K2) {
  const bits = byteToBits(byte);
  const ip = permute(bits, IP);
  const fk1 = fk(ip, K1);
  const swapped = fk1.slice(4).concat(fk1.slice(0, 4));
  const fk2 = fk(swapped, K2);
  const out = permute(fk2, IP_INV);
  return bitsToByte(out);
}

function sdesDecryptByte(byte, K1, K2) {
  const bits = byteToBits(byte);
  const ip = permute(bits, IP);
  const fk1 = fk(ip, K2);
  const swapped = fk1.slice(4).concat(fk1.slice(0, 4));
  const fk2 = fk(swapped, K1);
  const out = permute(fk2, IP_INV);
  return bitsToByte(out);
}

function fk(bits, subkey) {
  const left = bits.slice(0, 4);
  const right = bits.slice(4);
  const ep = permute(right, EP);
  const x = xor(ep, subkey);
  const s0 = sbox(x.slice(0, 4), S0);
  const s1 = sbox(x.slice(4), S1);
  const p4 = permute(s0.concat(s1), P4);
  const leftOut = xor(left, p4);
  return leftOut.concat(right);
}

function sbox(bits, box) {
  const row = (bits[0] << 1) | bits[3];
  const col = (bits[1] << 1) | bits[2];
  const val = box[row][col];
  return [ (val >> 1) & 1, val & 1 ];
}

function permute(bits, table) {
  return table.map((i) => bits[i - 1]);
}

function leftShift(bits, n) {
  return bits.slice(n).concat(bits.slice(0, n));
}

function xor(a, b) {
  return a.map((v, i) => v ^ b[i]);
}

function byteToBits(byte) {
  const out = [];
  for (let i = 7; i >= 0; i--) out.push((byte >> i) & 1);
  return out;
}

function bitsToByte(bits) {
  return bits.reduce((acc, b) => (acc << 1) | b, 0);
}

function keyTo10Bits(str) {
  const bytes = new TextEncoder().encode(str);
  const bits = [];
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  }
  while (bits.length < 10) bits.push(0);
  return bits.slice(0, 10);
}
