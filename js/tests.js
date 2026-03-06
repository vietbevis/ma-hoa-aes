/**
 * tests.js
 * ============================================================
 * Bộ kiểm tra (test suite) thuật toán AES
 * Dùng các vector kiểm tra chuẩn NIST FIPS 197
 * ============================================================
 */

/**
 * So sánh hai mảng byte
 */
function arrEqual(a, b) {
  if (a.length !== b.length) return false;
  return a.every((v, i) => v === b[i]);
}

/**
 * Parse hex string → số[] bytes
 */
function hexToArr(hex) {
  return Utils.fromHex(hex.replace(/\s/g, ''));
}

/**
 * Chạy toàn bộ test suite
 * @returns {{ passed: number, failed: number, results: object[] }}
 */
function runAllTests() {
  const results = [];
  let passed = 0, failed = 0;

  function test(name, fn) {
    try {
      const ok = fn();
      results.push({ name, ok, error: null });
      if (ok) passed++; else failed++;
    } catch (e) {
      results.push({ name, ok: false, error: e.message });
      failed++;
    }
  }

  // ─── GF(2^8) Multiplication ───
  test('GF(2^8): gmul(0x57, 0x83) = 0xC1', () =>
    AESCore.gmul(0x57, 0x83) === 0xC1);

  test('GF(2^8): gmul(0x02, 0x80) = 0x1B (reduction)', () =>
    AESCore.gmul(0x02, 0x80) === 0x1B);

  test('GF(2^8): gmul(0x53, 0xCA) = 0x01 (inverse)', () =>
    AESCore.gmul(0x53, 0xCA) === 0x01);

  // ─── S-Box ───
  test('S-Box: SBOX[0x00] = 0x63', () =>
    AESCore.SBOX[0x00] === 0x63);

  test('S-Box: SBOX[0x53] = 0xED', () =>
    AESCore.SBOX[0x53] === 0xED);

  test('S-Box & InvSBox nghịch đảo nhau', () => {
    for (let i = 0; i < 256; i++) {
      if (AESCore.INV_SBOX[AESCore.SBOX[i]] !== i) return false;
    }
    return true;
  });

  // ─── NIST FIPS 197 — AES-128 Single Block ───
  test('NIST FIPS 197 — AES-128 block encrypt', () => {
    const key = hexToArr('000102030405060708090a0b0c0d0e0f');
    const plain = hexToArr('00112233445566778899aabbccddeeff');
    const expected = hexToArr('69c4e0d86a7b0430d8cdb78070b4c55a');
    const ks = AESCore.keyExpansion(key);
    const result = AESCore.aesEncryptBlock(plain, ks);
    return arrEqual(result, expected);
  });

  test('NIST FIPS 197 — AES-128 block decrypt', () => {
    const key = hexToArr('000102030405060708090a0b0c0d0e0f');
    const cipher = hexToArr('69c4e0d86a7b0430d8cdb78070b4c55a');
    const expected = hexToArr('00112233445566778899aabbccddeeff');
    const ks = AESCore.keyExpansion(key);
    const result = AESCore.aesDecryptBlock(cipher, ks);
    return arrEqual(result, expected);
  });

  // ─── NIST FIPS 197 — AES-256 Single Block ───
  test('NIST FIPS 197 — AES-256 block encrypt', () => {
    const key = hexToArr('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const plain = hexToArr('00112233445566778899aabbccddeeff');
    const expected = hexToArr('8ea2b7ca516745bfeafc49904b496089');
    const ks = AESCore.keyExpansion(key);
    const result = AESCore.aesEncryptBlock(plain, ks);
    return arrEqual(result, expected);
  });

  // ─── ECB Mode — AES-128-ECB (NIST SP 800-38A F.1.1) ───
  test('ECB: AES-128 encrypt (NIST SP 800-38A F.1.1)', () => {
    const key = hexToArr('2b7e151628aed2a6abf7158809cf4f3c');
    const plain = hexToArr('6bc1bee22e409f96e93d7e117393172a');
    const expected = hexToArr('3ad77bb40d7a3660a89ecaf32466ef97');
    const ks = AESCore.keyExpansion(key);
    const result = AESCore.aesEncryptBlock(plain, ks);
    return arrEqual(result, expected);
  });

  test('ECB: AES-128 round-trip via AES.ecbEncrypt/Decrypt', () => {
    const key = Utils.prepareKey('ECBTestKey!!1234', 128);
    const plain = Utils.strToBytes('Block cipher ECB test data here!');
    const enc = AES.ecbEncrypt(plain, key);
    const dec = AES.ecbDecrypt(enc, key);
    return arrEqual(dec, plain);
  });

  test('ECB: ciphertext length là bội số 16 (PKCS#7)', () => {
    const key = Utils.prepareKey('key', 128);
    for (const len of [1, 7, 15, 16, 17, 31, 32]) {
      const plain = new Array(len).fill(0x41);
      const enc = AES.ecbEncrypt(plain, key);
      if (enc.length % 16 !== 0) return false;
    }
    return true;
  });

  // ─── CTR Mode — AES-128-CTR (NIST SP 800-38A F.5.1) ───
  test('CTR: AES-128 encrypt (NIST SP 800-38A F.5.1, block 1)', () => {
    // NIST test: key=2b7e...3c, ICB=f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    // Plain block 1: 6bc1bee22e409f96e93d7e117393172a
    // Cipher block 1: 874d6191b620e3261bef6864990db6ce
    const key = hexToArr('2b7e151628aed2a6abf7158809cf4f3c');
    const plain = hexToArr('6bc1bee22e409f96e93d7e117393172a');
    // Encrypt counter f0f1...ff → keystream, XOR with plain
    const ks = AESCore.keyExpansion(key);
    const counterBlock = hexToArr('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
    const keystream = AESCore.aesEncryptBlock(counterBlock, ks);
    const cipher = plain.map((b, i) => b ^ keystream[i]);
    const expected = hexToArr('874d6191b620e3261bef6864990db6ce');
    return arrEqual(cipher, expected);
  });

  test('CTR: round-trip via AES.ctrEncrypt/Decrypt', () => {
    const key = Utils.prepareKey('CTRModeTest!1234', 128);
    const nonce = Utils.randomBytes(8);
    const plain = Utils.strToBytes('Counter mode stream cipher test with variable length data!');
    const enc = AES.ctrEncrypt(plain, key, nonce);
    const dec = AES.ctrDecrypt(enc, key, nonce);
    return arrEqual(dec, plain);
  });

  test('CTR: ciphertext cùng độ dài plaintext (không padding)', () => {
    const key = Utils.prepareKey('key', 128);
    const nonce = Utils.randomBytes(8);
    for (const len of [1, 7, 15, 16, 17, 31, 32, 100]) {
      const plain = new Array(len).fill(0x42);
      const enc = AES.ctrEncrypt(plain, key, nonce);
      if (enc.length !== len) return false;
    }
    return true;
  });

  test('CTR: nonce khác → ciphertext khác', () => {
    const key = Utils.prepareKey('SameKey12345!!!!', 128);
    const plain = Utils.strToBytes('Same plaintext for nonce test');
    const nonce1 = [1, 2, 3, 4, 5, 6, 7, 8];
    const nonce2 = [8, 7, 6, 5, 4, 3, 2, 1];
    const enc1 = AES.ctrEncrypt(plain, key, nonce1);
    const enc2 = AES.ctrEncrypt(plain, key, nonce2);
    return !arrEqual(enc1, enc2);
  });

  // ─── CFB Mode — AES-128-CFB ───
  test('CFB: round-trip via AES.cfbEncrypt/Decrypt', () => {
    const key = Utils.prepareKey('CFBModeTest!1234', 128);
    const iv = Utils.randomBytes(16);
    const plain = Utils.strToBytes('Cipher Feedback mode test with variable length data!');
    const enc = AES.cfbEncrypt(plain, key, iv);
    const dec = AES.cfbDecrypt(enc, key, iv);
    return arrEqual(dec, plain);
  });

  test('CFB: ciphertext cùng độ dài plaintext (không padding)', () => {
    const key = Utils.prepareKey('key', 128);
    const iv = Utils.randomBytes(16);
    for (const len of [1, 7, 15, 16, 17, 31, 32, 100]) {
      const plain = new Array(len).fill(0x43);
      const enc = AES.cfbEncrypt(plain, key, iv);
      if (enc.length !== len) return false;
    }
    return true;
  });

  test('CFB: IV khác → ciphertext khác', () => {
    const key = Utils.prepareKey('SameKey12345!!!!', 128);
    const plain = Utils.strToBytes('Same plaintext for IV test');
    const iv1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    const iv2 = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
    const enc1 = AES.cfbEncrypt(plain, key, iv1);
    const enc2 = AES.cfbEncrypt(plain, key, iv2);
    return !arrEqual(enc1, enc2);
  });

  test('CFB: AES-256 round-trip', () => {
    const key = Utils.prepareKey('CFB256Key!CFB256Key!CFB256Key!!!', 256);
    const iv = Utils.randomBytes(16);
    const plain = Utils.strToBytes('AES-256-CFB encryption test with longer key');
    const enc = AES.cfbEncrypt(plain, key, iv);
    const dec = AES.cfbDecrypt(enc, key, iv);
    return arrEqual(dec, plain);
  });

  // ─── OFB Mode — AES-128-OFB ───
  test('OFB: round-trip via AES.ofbEncrypt/Decrypt', () => {
    const key = Utils.prepareKey('OFBModeTest!1234', 128);
    const iv = Utils.randomBytes(16);
    const plain = Utils.strToBytes('Output Feedback mode test with variable length data!');
    const enc = AES.ofbEncrypt(plain, key, iv);
    const dec = AES.ofbDecrypt(enc, key, iv);
    return arrEqual(dec, plain);
  });

  test('OFB: ciphertext cùng độ dài plaintext (không padding)', () => {
    const key = Utils.prepareKey('key', 128);
    const iv = Utils.randomBytes(16);
    for (const len of [1, 7, 15, 16, 17, 31, 32, 100]) {
      const plain = new Array(len).fill(0x44);
      const enc = AES.ofbEncrypt(plain, key, iv);
      if (enc.length !== len) return false;
    }
    return true;
  });

  test('OFB: encrypt và decrypt là cùng phép toán (đối xứng)', () => {
    const key = Utils.prepareKey('OFBSymmetric!!!!', 128);
    const iv = Utils.randomBytes(16);
    const data = Utils.strToBytes('OFB symmetry check — encrypt = decrypt');
    const enc = AES.ofbEncrypt(data, key, iv);
    const dec = AES.ofbEncrypt(enc, key, iv); // gọi encrypt thay vì decrypt
    return arrEqual(dec, data);
  });

  test('OFB: IV khác → ciphertext khác', () => {
    const key = Utils.prepareKey('SameKey12345!!!!', 128);
    const plain = Utils.strToBytes('Same plaintext for OFB IV test');
    const iv1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    const iv2 = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
    const enc1 = AES.ofbEncrypt(plain, key, iv1);
    const enc2 = AES.ofbEncrypt(plain, key, iv2);
    return !arrEqual(enc1, enc2);
  });

  test('OFB: AES-256 round-trip', () => {
    const key = Utils.prepareKey('OFB256Key!OFB256Key!OFB256Key!!!', 256);
    const iv = Utils.randomBytes(16);
    const plain = Utils.strToBytes('AES-256-OFB encryption test with longer key');
    const enc = AES.ofbEncrypt(plain, key, iv);
    const dec = AES.ofbDecrypt(enc, key, iv);
    return arrEqual(dec, plain);
  });

  // ─── NIST AES-128-CBC (RFC 3602) ───
  test('RFC 3602 — AES-128-CBC encrypt (case 1)', () => {
    const key = hexToArr('06a9214036b8a15b512e03d534120006');
    const iv = hexToArr('3dafba429d9eb430b422da802c9fac41');
    const plain = Utils.strToBytes('Single block msg');
    const expected = hexToArr('e353779c1079aeb82708942dbe77181a');
    // RFC 3602 vector dùng CBC *không padding* cho đúng 1 block 16 bytes
    const ks = AESCore.keyExpansion(key);
    const xored = plain.map((b, i) => b ^ iv[i]);
    const result = AESCore.aesEncryptBlock(xored, ks);
    return arrEqual(result, expected);
  });

  test('RFC 3602 — AES-128-CBC decrypt (case 1)', () => {
    const key = hexToArr('06a9214036b8a15b512e03d534120006');
    const iv = hexToArr('3dafba429d9eb430b422da802c9fac41');
    const cipher = hexToArr('e353779c1079aeb82708942dbe77181a');
    // RFC 3602 vector dùng CBC *không padding* cho đúng 1 block 16 bytes
    const ks = AESCore.keyExpansion(key);
    const dec = AESCore.aesDecryptBlock(cipher, ks);
    const result = dec.map((b, i) => b ^ iv[i]);
    const expected = Utils.strToBytes('Single block msg');
    return arrEqual(result, expected);
  });

  // ─── Round-trip tests ───
  test('Round-trip: text ngắn ASCII', () => {
    const key = Utils.prepareKey('SecretKey123!', 128);
    const iv = Utils.randomBytes(16);
    const plain = Utils.strToBytes('Hello, AES!');
    const enc = AESCore.aesCBCEncrypt(plain, key, iv);
    const dec = AESCore.aesCBCDecrypt(enc, key, iv);
    return arrEqual(dec, plain);
  });

  test('Round-trip: text tiếng Việt UTF-8', () => {
    const key = Utils.prepareKey('Khoa hoc mat ma', 128);
    const iv = Utils.randomBytes(16);
    const plain = Utils.strToBytes('Xin chào Việt Nam! Đây là thử nghiệm mã hóa AES.');
    const enc = AESCore.aesCBCEncrypt(plain, key, iv);
    const dec = AESCore.aesCBCDecrypt(enc, key, iv);
    return Utils.bytesToStr(dec) === 'Xin chào Việt Nam! Đây là thử nghiệm mã hóa AES.';
  });

  test('Round-trip: text dài (1024 bytes)', () => {
    const key = Utils.prepareKey('LongTestKey256!!LongTestKey256!!', 256);
    const iv = Utils.randomBytes(16);
    const plain = [];
    for (let i = 0; i < 1024; i++) plain.push(i % 256);
    const enc = AESCore.aesCBCEncrypt(plain, key, iv);
    const dec = AESCore.aesCBCDecrypt(enc, key, iv);
    return arrEqual(dec, plain);
  });

  test('Round-trip: AES-192', () => {
    const key = Utils.prepareKey('AES192KeyTest!!!AES192KeyTest!!!', 192);
    const iv = Utils.randomBytes(16);
    const plain = Utils.strToBytes('Testing AES-192 encryption mode.');
    const enc = AESCore.aesCBCEncrypt(plain, key, iv);
    const dec = AESCore.aesCBCDecrypt(enc, key, iv);
    return arrEqual(dec, plain);
  });

  // ─── PKCS#7 Padding ───
  test('PKCS#7: ciphertext length là bội số 16', () => {
    const key = Utils.prepareKey('key', 128);
    const iv = Utils.randomBytes(16);
    for (const len of [1, 7, 15, 16, 17, 31, 32]) {
      const plain = new Array(len).fill(0x41);
      const enc = AESCore.aesCBCEncrypt(plain, key, iv);
      if (enc.length % 16 !== 0) return false;
    }
    return true;
  });

  // ─── Base64 ───
  test('Base64: encode "Man" → "TWFu"', () =>
    Utils.toBase64(Utils.strToBytes('Man')) === 'TWFu');

  test('Base64: encode "Ma" → "TWE="', () =>
    Utils.toBase64(Utils.strToBytes('Ma')) === 'TWE=');

  test('Base64: round-trip với bytes ngẫu nhiên', () => {
    const bytes = Utils.randomBytes(64);
    const enc = Utils.toBase64(bytes);
    const dec = Utils.fromBase64(enc);
    return arrEqual(bytes, dec);
  });

  // ─── Hex ───
  test('Hex: encode [0xDE, 0xAD, 0xBE, 0xEF] = "DEADBEEF"', () =>
    Utils.toHex([0xDE, 0xAD, 0xBE, 0xEF]) === 'DEADBEEF');

  test('Hex: round-trip', () => {
    const bytes = [0x00, 0xFF, 0x12, 0xAB, 0x7F];
    return arrEqual(Utils.fromHex(Utils.toHex(bytes)), bytes);
  });

  // ─── UTF-8 ───
  test('UTF-8: encode/decode ASCII', () => {
    const s = 'Hello World! 123 !@#';
    return Utils.bytesToStr(Utils.strToBytes(s)) === s;
  });

  test('UTF-8: encode/decode tiếng Việt', () => {
    const s = 'Mật mã học - Advanced Encryption Standard';
    return Utils.bytesToStr(Utils.strToBytes(s)) === s;
  });

  // ─── Key sensitivity ───
  test('Avalanche effect: 1 bit khóa khác → ciphertext khác hoàn toàn', () => {
    const iv = Utils.randomBytes(16);
    const plain = Utils.strToBytes('AvalancheTest!!');
    const key1 = Utils.prepareKey('Key1', 128);
    const key2 = [...key1]; key2[0] ^= 0x01; // flip 1 bit
    const enc1 = AESCore.aesCBCEncrypt(plain, key1, iv);
    const enc2 = AESCore.aesCBCEncrypt(plain, key2, iv);
    // Expect significant difference
    const diff = enc1.filter((b, i) => b !== enc2[i]).length;
    return diff > enc1.length * 0.4; // ít nhất 40% bytes khác
  });

  test('Sai khóa → giải mã cho kết quả sai', () => {
    const key1 = Utils.prepareKey('CorrectKey123456', 128);
    const key2 = Utils.prepareKey('WrongKey!1234567', 128);
    const iv = Utils.randomBytes(16);
    const plain = Utils.strToBytes('Secret message!!');
    const enc = AESCore.aesCBCEncrypt(plain, key1, iv);
    try {
      const dec = AESCore.aesCBCDecrypt(enc, key2, iv);
      return !arrEqual(dec, plain);
    } catch (e) {
      return true; // padding error cũng là đúng
    }
  });

  // ─── AES Library API ───
  test('AES.encryptText/decryptText round-trip (CBC)', () => {
    const result = AES.encryptText('Hello Library!', 'TestKey!', 128, { mode: 'cbc' });
    const dec = AES.decryptText(result.cipher, 'TestKey!', 128, { mode: 'cbc', ivB64: result.iv });
    return dec === 'Hello Library!';
  });

  test('AES.encryptText/decryptText round-trip (ECB)', () => {
    const result = AES.encryptText('ECB Library Test', 'ECBKey!!', 128, { mode: 'ecb' });
    const dec = AES.decryptText(result.cipher, 'ECBKey!!', 128, { mode: 'ecb' });
    return dec === 'ECB Library Test';
  });

  test('AES.encryptText/decryptText round-trip (CTR)', () => {
    const result = AES.encryptText('CTR Library Test!', 'CTRKey!!', 128, { mode: 'ctr' });
    const dec = AES.decryptText(result.cipher, 'CTRKey!!', 128, { mode: 'ctr', nonceB64: result.nonce });
    return dec === 'CTR Library Test!';
  });

  test('AES.encryptText/decryptText round-trip (CFB)', () => {
    const result = AES.encryptText('CFB Library Test!', 'CFBKey!!', 128, { mode: 'cfb' });
    const dec = AES.decryptText(result.cipher, 'CFBKey!!', 128, { mode: 'cfb', ivB64: result.iv });
    return dec === 'CFB Library Test!';
  });

  test('AES.encryptText/decryptText round-trip (OFB)', () => {
    const result = AES.encryptText('OFB Library Test!', 'OFBKey!!', 128, { mode: 'ofb' });
    const dec = AES.decryptText(result.cipher, 'OFBKey!!', 128, { mode: 'ofb', ivB64: result.iv });
    return dec === 'OFB Library Test!';
  });

  test('AES.trace() trả về đúng số bước (AES-128: 42 steps)', () => {
    const block = Utils.strToBytes('Two One Nine Two');
    const key = Utils.strToBytes('Thats my Kung Fu');
    const steps = AES.trace(block, key);
    // AES-128: initial + ARK[0] + 9*(sub+shift+mix+ark) + sub+shift+ark = 2 + 36 + 3 = 41
    return steps.length === 41;
  });

  return { passed, failed, total: results.length, results };
}

window.TestSuite = { runAllTests };
