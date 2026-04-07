/**
 * aes-lib.js
 * ============================================================
 * Thư viện AES wrapper — tầng trên cùng cho dự án
 *
 * Load sau aes-core.js + utils.js. Cung cấp API thống nhất:
 *   window.AES = { encrypt, decrypt, encryptText, decryptText,
 *                  internal, trace, traceDec, util, modes }
 *
 * Tất cả 5 mode (ECB, CBC, CFB, OFB, CTR) được cài đặt trong aes-core.js.
 * File này cung cấp: unified API, trace cho visualizer, mode info cho UI.
 * Không sử dụng bất kỳ hàm crypto/encode có sẵn nào.
 * Tất cả 5 mode (ECB, CBC, CFB, OFB, CTR) được cài đặt trong aes-core.js.
 * File này cung cấp: unified API, trace cho visualizer, mode info cho UI.
 * Không sử dụng bất kỳ hàm crypto/encode có sẵn nào.
 *
 * Tác giả: Nguyễn Văn Việt, Trần Duy Quyến
 * Học viện Kỹ thuật Mật mã — Môn CSATBMTT
 * ============================================================
 */

(function () {
  'use strict';

  // ── Tham chiếu tới core & utils
  const Core = window.AESCore;
  const U = window.Utils;

  // ════════════════════════════════════════════
  //  UNIFIED ENCRYPT / DECRYPT API
  // ════════════════════════════════════════════

  /**
   * Mã hóa byte-level thống nhất cho cả 5 mode
   *
   * @param {number[]} plainBytes - dữ liệu gốc
   * @param {number[]} keyBytes   - khóa (16/24/32 bytes)
   * @param {Object}   opts       - { mode: 'ecb'|'cbc'|'cfb'|'ofb'|'ctr', iv?, nonce? }
   * @returns {number[]} ciphertext bytes
   */
  function encrypt(plainBytes, keyBytes, opts) {
    var mode = (opts && opts.mode) ? opts.mode.toLowerCase() : 'cbc';

    if (mode === 'ecb') {
      return Core.aesECBEncrypt(plainBytes, keyBytes);
    }
    if (mode === 'cbc') {
      var iv = opts && opts.iv;
      if (!iv) throw new Error('CBC mode cần IV 16 bytes');
      return Core.aesCBCEncrypt(plainBytes, keyBytes, iv);
    }
    if (mode === 'cfb') {
      var iv = opts && opts.iv;
      if (!iv) throw new Error('CFB mode cần IV 16 bytes');
      return Core.aesCFBEncrypt(plainBytes, keyBytes, iv);
    }
    if (mode === 'ofb') {
      var iv = opts && opts.iv;
      if (!iv) throw new Error('OFB mode cần IV 16 bytes');
      return Core.aesOFBEncrypt(plainBytes, keyBytes, iv);
    }
    if (mode === 'ctr') {
      var nonce = opts && opts.nonce;
      if (!nonce) throw new Error('CTR mode cần nonce 8 bytes');
      return Core.aesCTREncrypt(plainBytes, keyBytes, nonce);
    }
    throw new Error('Mode không hợp lệ: ' + mode + '. Chọn ecb, cbc, cfb, ofb hoặc ctr');
  }

  /**
   * Giải mã byte-level thống nhất cho cả 5 mode
   *
   * @param {number[]} cipherBytes - dữ liệu đã mã hóa
   * @param {number[]} keyBytes    - khóa (16/24/32 bytes)
   * @param {Object}   opts        - { mode: 'ecb'|'cbc'|'cfb'|'ofb'|'ctr', iv?, nonce? }
   * @returns {number[]} plaintext bytes
   */
  function decrypt(cipherBytes, keyBytes, opts) {
    var mode = (opts && opts.mode) ? opts.mode.toLowerCase() : 'cbc';

    if (mode === 'ecb') {
      return Core.aesECBDecrypt(cipherBytes, keyBytes);
    }
    if (mode === 'cbc') {
      var iv = opts && opts.iv;
      if (!iv) throw new Error('CBC mode cần IV 16 bytes');
      return Core.aesCBCDecrypt(cipherBytes, keyBytes, iv);
    }
    if (mode === 'cfb') {
      var iv = opts && opts.iv;
      if (!iv) throw new Error('CFB mode cần IV 16 bytes');
      return Core.aesCFBDecrypt(cipherBytes, keyBytes, iv);
    }
    if (mode === 'ofb') {
      var iv = opts && opts.iv;
      if (!iv) throw new Error('OFB mode cần IV 16 bytes');
      return Core.aesOFBDecrypt(cipherBytes, keyBytes, iv);
    }
    if (mode === 'ctr') {
      var nonce = opts && opts.nonce;
      if (!nonce) throw new Error('CTR mode cần nonce 8 bytes');
      return Core.aesCTRDecrypt(cipherBytes, keyBytes, nonce);
    }
    throw new Error('Mode không hợp lệ: ' + mode + '. Chọn ecb, cbc, cfb, ofb hoặc ctr');
  }

  // ════════════════════════════════════════════
  //  HIGH-LEVEL TEXT ENCRYPT / DECRYPT
  // ════════════════════════════════════════════

  /**
   * Mã hóa text → object chứa ciphertext Base64 + metadata
   *
   * @param {string} plaintext - chuỗi văn bản
   * @param {string} keyStr    - chuỗi khóa
   * @param {number} keyBits   - 128/192/256
   * @param {Object} opts      - { mode: 'ecb'|'cbc'|'cfb'|'ofb'|'ctr', iv?, nonce? }
   * @returns {{ cipher: string, iv?: string, nonce?: string, keyHex: string, mode: string }}
   */
  function encryptText(plaintext, keyStr, keyBits, opts) {
    var mode = (opts && opts.mode) ? opts.mode.toLowerCase() : 'cbc';
    var keyBytes = U.prepareKey(keyStr, keyBits);
    var plainBytes = U.strToBytes(plaintext);
    var result = { mode: mode, keyHex: U.toHex(keyBytes) };

    if (mode === 'ecb') {
      var cipher = Core.aesECBEncrypt(plainBytes, keyBytes);
      var cipher = Core.aesECBEncrypt(plainBytes, keyBytes);
      result.cipher = U.toBase64(cipher);
    } else if (mode === 'cbc') {
      var iv = (opts && opts.iv) ? opts.iv : U.randomBytes(16);
      var cipher = Core.aesCBCEncrypt(plainBytes, keyBytes, iv);
      result.cipher = U.toBase64(cipher);
      result.iv = U.toBase64(iv);
    } else if (mode === 'cfb') {
      var iv = (opts && opts.iv) ? opts.iv : U.randomBytes(16);
      var cipher = Core.aesCFBEncrypt(plainBytes, keyBytes, iv);
      var cipher = Core.aesCFBEncrypt(plainBytes, keyBytes, iv);
      result.cipher = U.toBase64(cipher);
      result.iv = U.toBase64(iv);
    } else if (mode === 'ofb') {
      var iv = (opts && opts.iv) ? opts.iv : U.randomBytes(16);
      var cipher = Core.aesOFBEncrypt(plainBytes, keyBytes, iv);
      var cipher = Core.aesOFBEncrypt(plainBytes, keyBytes, iv);
      result.cipher = U.toBase64(cipher);
      result.iv = U.toBase64(iv);
    } else if (mode === 'ctr') {
      var nonce = (opts && opts.nonce) ? opts.nonce : U.randomBytes(8);
      var cipher = Core.aesCTREncrypt(plainBytes, keyBytes, nonce);
      var cipher = Core.aesCTREncrypt(plainBytes, keyBytes, nonce);
      result.cipher = U.toBase64(cipher);
      result.nonce = U.toBase64(nonce);
    } else {
      throw new Error('Mode không hợp lệ: ' + mode);
    }
    return result;
  }

  /**
   * Giải mã text từ ciphertext Base64 + metadata
   *
   * @param {string} cipherB64 - ciphertext Base64
   * @param {string} keyStr    - chuỗi khóa
   * @param {number} keyBits   - 128/192/256
   * @param {Object} opts      - { mode, ivB64?, nonceB64? }
   * @returns {string} plaintext
   */
  function decryptText(cipherB64, keyStr, keyBits, opts) {
    var mode = (opts && opts.mode) ? opts.mode.toLowerCase() : 'cbc';
    var keyBytes = U.prepareKey(keyStr, keyBits);
    var cipherBytes = U.fromBase64(cipherB64);
    var plainBytes;

    if (mode === 'ecb') {
      plainBytes = Core.aesECBDecrypt(cipherBytes, keyBytes);
      plainBytes = Core.aesECBDecrypt(cipherBytes, keyBytes);
    } else if (mode === 'cbc') {
      var iv = opts && opts.ivB64 ? U.fromBase64(opts.ivB64) : null;
      if (!iv) throw new Error('CBC giải mã cần IV (Base64)');
      plainBytes = Core.aesCBCDecrypt(cipherBytes, keyBytes, iv);
    } else if (mode === 'cfb') {
      var iv = opts && opts.ivB64 ? U.fromBase64(opts.ivB64) : null;
      if (!iv) throw new Error('CFB giải mã cần IV (Base64)');
      plainBytes = Core.aesCFBDecrypt(cipherBytes, keyBytes, iv);
      plainBytes = Core.aesCFBDecrypt(cipherBytes, keyBytes, iv);
    } else if (mode === 'ofb') {
      var iv = opts && opts.ivB64 ? U.fromBase64(opts.ivB64) : null;
      if (!iv) throw new Error('OFB giải mã cần IV (Base64)');
      plainBytes = Core.aesOFBDecrypt(cipherBytes, keyBytes, iv);
      plainBytes = Core.aesOFBDecrypt(cipherBytes, keyBytes, iv);
    } else if (mode === 'ctr') {
      var nonce = opts && opts.nonceB64 ? U.fromBase64(opts.nonceB64) : null;
      if (!nonce) throw new Error('CTR giải mã cần Nonce (Base64)');
      plainBytes = Core.aesCTRDecrypt(cipherBytes, keyBytes, nonce);
      plainBytes = Core.aesCTRDecrypt(cipherBytes, keyBytes, nonce);
    } else {
      throw new Error('Mode không hợp lệ: ' + mode);
    }
    return U.bytesToStr(plainBytes);
  }

  // ════════════════════════════════════════════
  //  FILE ENCRYPT / DECRYPT (AESF CONTAINER)
  // ════════════════════════════════════════════

  // AESF container format (v2):
  //  [4 bytes: magic "AESF"]
  //  [1 byte: 0x00 marker (v2)]
  //  [1 byte: keyBits/64 → 2/3/4]
  //  [1 byte: mode id (0=ECB,1=CBC,2=CTR,3=CFB,4=OFB)]
  //  [16 bytes: IV/Nonce padded to 16 bytes]
  //  [4 bytes: filename length] [N bytes: filename UTF-8]
  //  [4 bytes: mime length]     [M bytes: mime UTF-8]
  //  [rest: ciphertext bytes]
  const AESF_MAGIC = [0x41, 0x45, 0x53, 0x46]; // "AESF"
  const AESF_MODE_MAP = { ecb: 0, cbc: 1, ctr: 2, cfb: 3, ofb: 4 };
  const AESF_MODE_NAMES = ['ecb', 'cbc', 'ctr', 'cfb', 'ofb'];

  function appendBytes(target, source) {
    for (let i = 0; i < source.length; i++) target.push(source[i]);
  }

  function buildAESFContainer(keyBits, ivOrNonce, filename, mimeType, cipherBytes, mode) {
    const fnBytes = U.strToBytes(filename || 'encrypted.bin');
    const mimeBytes = U.strToBytes(mimeType || 'application/octet-stream');
    const out = [];

    appendBytes(out, AESF_MAGIC);
    out.push(0x00); // v2 marker
    out.push(keyBits / 64);
    out.push(AESF_MODE_MAP[mode] != null ? AESF_MODE_MAP[mode] : 1);

    const ivPad = (ivOrNonce || []).slice(0, 16);
    while (ivPad.length < 16) ivPad.push(0);
    appendBytes(out, ivPad);

    out.push(
      (fnBytes.length >> 24) & 0xff,
      (fnBytes.length >> 16) & 0xff,
      (fnBytes.length >> 8) & 0xff,
      fnBytes.length & 0xff,
    );
    appendBytes(out, fnBytes);

    out.push(
      (mimeBytes.length >> 24) & 0xff,
      (mimeBytes.length >> 16) & 0xff,
      (mimeBytes.length >> 8) & 0xff,
      mimeBytes.length & 0xff,
    );
    appendBytes(out, mimeBytes);

    appendBytes(out, cipherBytes);
    return out;
  }

  function parseAESFContainer(bytes) {
    const arr = Array.isArray(bytes) ? bytes : Array.from(bytes);
    let pos = 0;

    for (let i = 0; i < 4; i++) {
      if (arr[pos++] !== AESF_MAGIC[i]) {
        throw new Error('Không phải file .aes hợp lệ (magic mismatch)');
      }
    }

    let keyBits, iv, mode;
    if (arr[pos] === 0x00) {
      pos++;
      keyBits = arr[pos++] * 64;
      mode = AESF_MODE_NAMES[arr[pos++]] || 'cbc';
      iv = arr.slice(pos, pos + 16);
      pos += 16;
    } else {
      // legacy v1: [keyBits/64][16 IV][...cipher], always CBC
      keyBits = arr[pos++] * 64;
      mode = 'cbc';
      iv = arr.slice(pos, pos + 16);
      pos += 16;
    }

    const fnLen =
      (arr[pos] << 24) |
      (arr[pos + 1] << 16) |
      (arr[pos + 2] << 8) |
      arr[pos + 3];
    pos += 4;
    const filename = U.bytesToStr(arr.slice(pos, pos + fnLen));
    pos += fnLen;

    const mimeLen =
      (arr[pos] << 24) |
      (arr[pos + 1] << 16) |
      (arr[pos + 2] << 8) |
      arr[pos + 3];
    pos += 4;
    const mimeType = U.bytesToStr(arr.slice(pos, pos + mimeLen));
    pos += mimeLen;

    const cipher = arr.slice(pos);
    return { keyBits, iv, filename, mimeType, cipher, mode };
  }

  /**
   * Mã hóa file bytes → AESF container bytes
   *
   * @param {Uint8Array|number[]} fileBytes
   * @param {string} filename
   * @param {string} mimeType
   * @param {string} keyStr
   * @param {number} keyBits 128/192/256
   * @param {{mode?: string, iv?: number[], nonce?: number[]}} opts
   */
  function encryptFile(fileBytes, filename, mimeType, keyStr, keyBits, opts) {
    const mode = (opts && opts.mode) ? opts.mode.toLowerCase() : 'cbc';
    const data = Array.isArray(fileBytes) ? fileBytes : Array.from(fileBytes);
    const keyBytes = U.prepareKey(keyStr, keyBits);

    let ivOrNonce;
    if (mode === 'ecb') {
      ivOrNonce = new Array(16).fill(0);
    } else if (mode === 'ctr') {
      ivOrNonce = (opts && opts.nonce) ? opts.nonce.slice(0, 8) : U.randomBytes(8);
    } else {
      ivOrNonce = (opts && opts.iv) ? opts.iv.slice(0, 16) : U.randomBytes(16);
    }

    const aesOpts = { mode };
    if (mode === 'cbc' || mode === 'cfb' || mode === 'ofb') aesOpts.iv = ivOrNonce;
    if (mode === 'ctr') aesOpts.nonce = ivOrNonce;

    const cipherBytes = encrypt(data, keyBytes, aesOpts);
    const container = buildAESFContainer(keyBits, ivOrNonce, filename, mimeType, cipherBytes, mode);
    return {
      container,
      cipherBytes,
      outName: (filename || 'encrypted.bin') + '.aes',
      keyHex: U.toHex(keyBytes),
      keyBits,
      mode,
      iv: (mode === 'cbc' || mode === 'cfb' || mode === 'ofb') ? ivOrNonce : null,
      nonce: (mode === 'ctr') ? ivOrNonce : null
    };
  }

  /**
   * Giải mã AESF container bytes → file bytes
   *
   * @param {Uint8Array|number[]} containerBytes
   * @param {string} keyStr
   * @param {number} keyBitsOverride 128/192/256 (UI chọn); nếu null sẽ dùng embedded keyBits
   * @param {{iv?: number[], nonce?: number[]}} opts
   */
  function decryptFile(containerBytes, keyStr, keyBitsOverride, opts) {
    const raw = Array.isArray(containerBytes) ? containerBytes : Array.from(containerBytes);
    const parsed = parseAESFContainer(raw);

    const mode = (parsed.mode || 'cbc').toLowerCase();
    const keyBits = keyBitsOverride || parsed.keyBits || 128;
    const keyBytes = U.prepareKey(keyStr, keyBits);

    let ivOrNonce = parsed.iv;
    if (mode === 'ctr' && opts && opts.nonce) ivOrNonce = opts.nonce.slice(0, 8);
    if ((mode === 'cbc' || mode === 'cfb' || mode === 'ofb') && opts && opts.iv) ivOrNonce = opts.iv.slice(0, 16);

    const aesOpts = { mode };
    if (mode === 'cbc' || mode === 'cfb' || mode === 'ofb') aesOpts.iv = ivOrNonce;
    if (mode === 'ctr') aesOpts.nonce = ivOrNonce.slice(0, 8);

    const plainBytes = decrypt(parsed.cipher, keyBytes, aesOpts);
    return {
      plainBytes,
      filename: parsed.filename || 'decrypted.bin',
      mimeType: parsed.mimeType || 'application/octet-stream',
      mode,
      embeddedKeyBits: parsed.keyBits,
      keyBitsUsed: keyBits,
      cipherBytesLength: parsed.cipher.length,
      iv: (mode === 'cbc' || mode === 'cfb' || mode === 'ofb') ? ivOrNonce : null,
      nonce: (mode === 'ctr') ? ivOrNonce.slice(0, 8) : null
    };
  }

  // ════════════════════════════════════════════
  //  FILE ENCRYPT / DECRYPT (AESF CONTAINER)
  // ════════════════════════════════════════════

  // AESF container format (v2):
  //  [4 bytes: magic "AESF"]
  //  [1 byte: 0x00 marker (v2)]
  //  [1 byte: keyBits/64 → 2/3/4]
  //  [1 byte: mode id (0=ECB,1=CBC,2=CTR,3=CFB,4=OFB)]
  //  [16 bytes: IV/Nonce padded to 16 bytes]
  //  [4 bytes: filename length] [N bytes: filename UTF-8]
  //  [4 bytes: mime length]     [M bytes: mime UTF-8]
  //  [rest: ciphertext bytes]

  function appendBytes(target, source) {
    for (let i = 0; i < source.length; i++) target.push(source[i]);
  }

  function buildAESFContainer(keyBits, ivOrNonce, filename, mimeType, cipherBytes, mode) {
    const fnBytes = U.strToBytes(filename || 'encrypted.bin');
    const mimeBytes = U.strToBytes(mimeType || 'application/octet-stream');
    const out = [];

    appendBytes(out, AESF_MAGIC);
    out.push(0x00); // v2 marker
    out.push(keyBits / 64);
    out.push(AESF_MODE_MAP[mode] != null ? AESF_MODE_MAP[mode] : 1);

    const ivPad = (ivOrNonce || []).slice(0, 16);
    while (ivPad.length < 16) ivPad.push(0);
    appendBytes(out, ivPad);

    out.push(
      (fnBytes.length >> 24) & 0xff,
      (fnBytes.length >> 16) & 0xff,
      (fnBytes.length >> 8) & 0xff,
      fnBytes.length & 0xff,
    );
    appendBytes(out, fnBytes);

    out.push(
      (mimeBytes.length >> 24) & 0xff,
      (mimeBytes.length >> 16) & 0xff,
      (mimeBytes.length >> 8) & 0xff,
      mimeBytes.length & 0xff,
    );
    appendBytes(out, mimeBytes);

    appendBytes(out, cipherBytes);
    return out;
  }

  function parseAESFContainer(bytes) {
    const arr = Array.isArray(bytes) ? bytes : Array.from(bytes);
    let pos = 0;

    for (let i = 0; i < 4; i++) {
      if (arr[pos++] !== AESF_MAGIC[i]) {
        throw new Error('Không phải file .aes hợp lệ (magic mismatch)');
      }
    }

    let keyBits, iv, mode;
    if (arr[pos] === 0x00) {
      pos++;
      keyBits = arr[pos++] * 64;
      mode = AESF_MODE_NAMES[arr[pos++]] || 'cbc';
      iv = arr.slice(pos, pos + 16);
      pos += 16;
    } else {
      // legacy v1: [keyBits/64][16 IV][...cipher], always CBC
      keyBits = arr[pos++] * 64;
      mode = 'cbc';
      iv = arr.slice(pos, pos + 16);
      pos += 16;
    }

    const fnLen =
      (arr[pos] << 24) |
      (arr[pos + 1] << 16) |
      (arr[pos + 2] << 8) |
      arr[pos + 3];
    pos += 4;
    const filename = U.bytesToStr(arr.slice(pos, pos + fnLen));
    pos += fnLen;

    const mimeLen =
      (arr[pos] << 24) |
      (arr[pos + 1] << 16) |
      (arr[pos + 2] << 8) |
      arr[pos + 3];
    pos += 4;
    const mimeType = U.bytesToStr(arr.slice(pos, pos + mimeLen));
    pos += mimeLen;

    const cipher = arr.slice(pos);
    return { keyBits, iv, filename, mimeType, cipher, mode };
  }

  /**
   * Mã hóa file bytes → AESF container bytes
   *
   * @param {Uint8Array|number[]} fileBytes
   * @param {string} filename
   * @param {string} mimeType
   * @param {string} keyStr
   * @param {number} keyBits 128/192/256
   * @param {{mode?: string, iv?: number[], nonce?: number[]}} opts
   */
  function encryptFile(fileBytes, filename, mimeType, keyStr, keyBits, opts) {
    const mode = (opts && opts.mode) ? opts.mode.toLowerCase() : 'cbc';
    const data = Array.isArray(fileBytes) ? fileBytes : Array.from(fileBytes);
    const keyBytes = U.prepareKey(keyStr, keyBits);

    let ivOrNonce;
    if (mode === 'ecb') {
      ivOrNonce = new Array(16).fill(0);
    } else if (mode === 'ctr') {
      ivOrNonce = (opts && opts.nonce) ? opts.nonce.slice(0, 8) : U.randomBytes(8);
    } else {
      ivOrNonce = (opts && opts.iv) ? opts.iv.slice(0, 16) : U.randomBytes(16);
    }

    const aesOpts = { mode };
    if (mode === 'cbc' || mode === 'cfb' || mode === 'ofb') aesOpts.iv = ivOrNonce;
    if (mode === 'ctr') aesOpts.nonce = ivOrNonce;

    const cipherBytes = encrypt(data, keyBytes, aesOpts);
    const container = buildAESFContainer(keyBits, ivOrNonce, filename, mimeType, cipherBytes, mode);
    return {
      container,
      cipherBytes,
      outName: (filename || 'encrypted.bin') + '.aes',
      keyHex: U.toHex(keyBytes),
      keyBits,
      mode,
      iv: (mode === 'cbc' || mode === 'cfb' || mode === 'ofb') ? ivOrNonce : null,
      nonce: (mode === 'ctr') ? ivOrNonce : null
    };
  }

  /**
   * Giải mã AESF container bytes → file bytes
   *
   * @param {Uint8Array|number[]} containerBytes
   * @param {string} keyStr
   * @param {number} keyBitsOverride 128/192/256 (UI chọn); nếu null sẽ dùng embedded keyBits
   * @param {{iv?: number[], nonce?: number[]}} opts
   */
  function decryptFile(containerBytes, keyStr, keyBitsOverride, opts) {
    const raw = Array.isArray(containerBytes) ? containerBytes : Array.from(containerBytes);
    const parsed = parseAESFContainer(raw);

    const mode = (parsed.mode || 'cbc').toLowerCase();
    const keyBits = keyBitsOverride || parsed.keyBits || 128;
    const keyBytes = U.prepareKey(keyStr, keyBits);

    let ivOrNonce = parsed.iv;
    if (mode === 'ctr' && opts && opts.nonce) ivOrNonce = opts.nonce.slice(0, 8);
    if ((mode === 'cbc' || mode === 'cfb' || mode === 'ofb') && opts && opts.iv) ivOrNonce = opts.iv.slice(0, 16);

    const aesOpts = { mode };
    if (mode === 'cbc' || mode === 'cfb' || mode === 'ofb') aesOpts.iv = ivOrNonce;
    if (mode === 'ctr') aesOpts.nonce = ivOrNonce.slice(0, 8);

    const plainBytes = decrypt(parsed.cipher, keyBytes, aesOpts);
    return {
      plainBytes,
      filename: parsed.filename || 'decrypted.bin',
      mimeType: parsed.mimeType || 'application/octet-stream',
      mode,
      embeddedKeyBits: parsed.keyBits,
      keyBitsUsed: keyBits,
      cipherBytesLength: parsed.cipher.length,
      iv: (mode === 'cbc' || mode === 'cfb' || mode === 'ofb') ? ivOrNonce : null,
      nonce: (mode === 'ctr') ? ivOrNonce.slice(0, 8) : null
    };
  }

  // ════════════════════════════════════════════
  //  TRACE — cho Visualizer
  // ════════════════════════════════════════════

  /**
   * Trace quá trình mã hóa 1 block AES
   * Trả về mảng các bước trung gian
   *
   * @param {number[]} block - 16 bytes plaintext
   * @param {number[]} key   - khóa bytes
   * @returns {Array<{ round: number, label: string, state: number[][], highlight: string }>}
   */
  function trace(block, key) {
    var ks = Core.keyExpansion(key);
    var w = ks.w, Nr = ks.Nr;
    var steps = [];

    function capture(state, round, label, highlight) {
      steps.push({
        round: round,
        label: label,
        state: state.map(function (r) { return r.slice(); }),
        highlight: highlight || 'none'
      });
    }

    var state = Core.bytesToState(block);
    capture(state, 0, 'Initial State', 'none');

    state = Core.addRoundKey(state, w, 0);
    capture(state, 0, 'AddRoundKey[0]', 'ark');

    for (var round = 1; round < Nr; round++) {
      state = Core.subBytes(state);
      capture(state, round, 'R' + round + ': SubBytes', 'sub');
      state = Core.shiftRows(state);
      capture(state, round, 'R' + round + ': ShiftRows', 'shift');
      state = Core.mixColumns(state);
      capture(state, round, 'R' + round + ': MixColumns', 'mix');
      state = Core.addRoundKey(state, w, round);
      capture(state, round, 'R' + round + ': AddRoundKey', 'ark');
    }

    // Vòng cuối
    state = Core.subBytes(state);
    capture(state, Nr, 'R' + Nr + ': SubBytes', 'sub');
    state = Core.shiftRows(state);
    capture(state, Nr, 'R' + Nr + ': ShiftRows (Final)', 'shift');
    state = Core.addRoundKey(state, w, Nr);
    capture(state, Nr, 'R' + Nr + ': AddRoundKey (Output)', 'ark');

    return steps;
  }

  /**
   * Trace quá trình giải mã 1 block AES
   *
   * @param {number[]} block - 16 bytes ciphertext
   * @param {number[]} key   - khóa bytes
   * @returns {Array<{ round: number, label: string, state: number[][], highlight: string }>}
   */
  function traceDec(block, key) {
    var ks = Core.keyExpansion(key);
    var w = ks.w, Nr = ks.Nr;
    var steps = [];

    function capture(state, round, label, highlight) {
      steps.push({
        round: round,
        label: label,
        state: state.map(function (r) { return r.slice(); }),
        highlight: highlight || 'none'
      });
    }

    var state = Core.bytesToState(block);
    capture(state, Nr, 'Initial Ciphertext', 'none');

    state = Core.addRoundKey(state, w, Nr);
    capture(state, Nr, 'AddRoundKey[' + Nr + ']', 'ark');

    for (var round = Nr - 1; round >= 1; round--) {
      state = Core.invShiftRows(state);
      capture(state, round, 'R' + round + ': InvShiftRows', 'shift');
      state = Core.invSubBytes(state);
      capture(state, round, 'R' + round + ': InvSubBytes', 'sub');
      state = Core.addRoundKey(state, w, round);
      capture(state, round, 'R' + round + ': AddRoundKey', 'ark');
      state = Core.invMixColumns(state);
      capture(state, round, 'R' + round + ': InvMixColumns', 'mix');
    }

    // Vòng cuối
    state = Core.invShiftRows(state);
    capture(state, 0, 'R0: InvShiftRows', 'shift');
    state = Core.invSubBytes(state);
    capture(state, 0, 'R0: InvSubBytes', 'sub');
    state = Core.addRoundKey(state, w, 0);
    capture(state, 0, 'R0: AddRoundKey (Output)', 'ark');

    return steps;
  }

  // ════════════════════════════════════════════
  //  MODE INFO — cho UI
  // ════════════════════════════════════════════

  var modes = {
    ecb: {
      name: 'ECB',
      fullName: 'Electronic Codebook',
      needsIV: false,
      needsNonce: false,
      needsPadding: true,
      parallel: true,
      security: 'weak',
      description: 'Mỗi block được mã hóa độc lập. Không an toàn cho dữ liệu có pattern lặp.',
      warning: '⚠️ ECB không an toàn: plaintext giống nhau → ciphertext giống nhau. Chỉ nên dùng cho mục đích học thuật.'
    },
    cbc: {
      name: 'CBC',
      fullName: 'Cipher Block Chaining',
      needsIV: true,
      needsNonce: false,
      needsPadding: true,
      parallel: false,
      security: 'good',
      description: 'Mỗi block plaintext được XOR với ciphertext của block trước rồi mới mã hóa.',
      warning: null
    },
    cfb: {
      name: 'CFB',
      fullName: 'Cipher Feedback',
      needsIV: true,
      needsNonce: false,
      needsPadding: false,
      parallel: false,
      security: 'good',
      description: 'Mã hóa shift register rồi XOR với plaintext. Kết quả ciphertext được dùng làm feedback cho block tiếp theo.',
      warning: null
    },
    ofb: {
      name: 'OFB',
      fullName: 'Output Feedback',
      needsIV: true,
      needsNonce: false,
      needsPadding: false,
      parallel: false,
      security: 'good',
      description: 'Mã hóa feedback block rồi XOR với plaintext. Feedback chỉ phụ thuộc vào key và IV, không phụ thuộc dữ liệu.',
      warning: null
    },
    ctr: {
      name: 'CTR',
      fullName: 'Counter Mode',
      needsIV: false,
      needsNonce: true,
      needsPadding: false,
      parallel: true,
      security: 'good',
      description: 'Mã hóa counter block rồi XOR với plaintext. Hoạt động như stream cipher.',
      warning: null
    }
  };

  // ════════════════════════════════════════════
  //  EXPORT — window.AES
  // ════════════════════════════════════════════

  window.AES = {
    // ── High-level API
    encrypt: encrypt,
    decrypt: decrypt,
    encryptText: encryptText,
    decryptText: decryptText,

    // ── File API (AESF container)
    encryptFile: encryptFile,
    decryptFile: decryptFile,

    // ── Low-level mode functions (tất cả từ aes-core.js)
    ecbEncrypt: Core.aesECBEncrypt,
    ecbDecrypt: Core.aesECBDecrypt,
    // ── File API (AESF container)
    encryptFile: encryptFile,
    decryptFile: decryptFile,

    // ── Low-level mode functions (tất cả từ aes-core.js)
    ecbEncrypt: Core.aesECBEncrypt,
    ecbDecrypt: Core.aesECBDecrypt,
    cbcEncrypt: Core.aesCBCEncrypt,
    cbcDecrypt: Core.aesCBCDecrypt,
    cfbEncrypt: Core.aesCFBEncrypt,
    cfbDecrypt: Core.aesCFBDecrypt,
    ofbEncrypt: Core.aesOFBEncrypt,
    ofbDecrypt: Core.aesOFBDecrypt,
    ctrEncrypt: Core.aesCTREncrypt,
    ctrDecrypt: Core.aesCTRDecrypt,
    cfbEncrypt: Core.aesCFBEncrypt,
    cfbDecrypt: Core.aesCFBDecrypt,
    ofbEncrypt: Core.aesOFBEncrypt,
    ofbDecrypt: Core.aesOFBDecrypt,
    ctrEncrypt: Core.aesCTREncrypt,
    ctrDecrypt: Core.aesCTRDecrypt,

    // ── Block-level
    encryptBlock: Core.aesEncryptBlock,
    decryptBlock: Core.aesDecryptBlock,
    keyExpansion: Core.keyExpansion,

    // ── Internal transforms (cho visualizer)
    internal: {
      bytesToState: Core.bytesToState,
      stateToBytes: Core.stateToBytes,
      subBytes: Core.subBytes,
      invSubBytes: Core.invSubBytes,
      shiftRows: Core.shiftRows,
      invShiftRows: Core.invShiftRows,
      mixColumns: Core.mixColumns,
      invMixColumns: Core.invMixColumns,
      addRoundKey: Core.addRoundKey,
      keyExpansion: Core.keyExpansion,
      SBOX: Core.SBOX,
      INV_SBOX: Core.INV_SBOX,
      gmul: Core.gmul,
      pkcs7Pad: Core.pkcs7Pad,
      pkcs7Unpad: Core.pkcs7Unpad,
      incrementCounter: Core.incrementCounter,
      pkcs7Pad: Core.pkcs7Pad,
      pkcs7Unpad: Core.pkcs7Unpad,
      incrementCounter: Core.incrementCounter
    },

    // ── Trace (cho visualizer)
    trace: trace,
    traceDec: traceDec,

    // ── Utility forwards
    util: {
      strToBytes: U.strToBytes,
      bytesToStr: U.bytesToStr,
      toBase64: U.toBase64,
      fromBase64: U.fromBase64,
      toHex: U.toHex,
      fromHex: U.fromHex,
      randomBytes: U.randomBytes,
      keyByteLength: U.keyByteLength,
      validateKeyLength: U.validateKeyLength,
      prepareKey: U.prepareKey,
      validateInputs: U.validateInputs,
      formatHexDump: U.formatHexDump
    },

    // ── Mode info
    modes: modes
  };

})();