/**
 * aes-lib.js
 * ============================================================
 * Thư viện AES wrapper — tầng trên cùng cho dự án
 *
 * Load sau aes-core.js + utils.js. Cung cấp API thống nhất:
 *   window.AES = { encrypt, decrypt, encryptText, decryptText,
 *                  internal, trace, traceDec, util, modes }
 *
 * Hỗ trợ 5 mode: ECB, CBC, CFB, OFB, CTR
 * Tự cài đặt: ECB, CFB, OFB, CTR, internal transforms, counter increment
 * Không sử dụng bất kỳ hàm crypto/encode có sẵn nào
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
  //  INTERNAL TRANSFORMS (tự cài đặt lại vì core không export)
  // ════════════════════════════════════════════

  /**
   * Chuyển 16 bytes → ma trận state 4×4 (column-major)
   */
  function bytesToState(block) {
    const s = [
      [0, 0, 0, 0],
      [0, 0, 0, 0],
      [0, 0, 0, 0],
      [0, 0, 0, 0]
    ];
    for (let r = 0; r < 4; r++)
      for (let c = 0; c < 4; c++)
        s[r][c] = block[r + 4 * c];
    return s;
  }

  /**
   * Chuyển ma trận state 4×4 → 16 bytes
   */
  function stateToBytes(state) {
    const b = new Array(16);
    for (let r = 0; r < 4; r++)
      for (let c = 0; c < 4; c++)
        b[r + 4 * c] = state[r][c];
    return b;
  }

  /**
   * SubBytes — thay thế qua S-Box
   */
  function subBytes(state) {
    const SBOX = Core.SBOX;
    return [
      [SBOX[state[0][0]], SBOX[state[0][1]], SBOX[state[0][2]], SBOX[state[0][3]]],
      [SBOX[state[1][0]], SBOX[state[1][1]], SBOX[state[1][2]], SBOX[state[1][3]]],
      [SBOX[state[2][0]], SBOX[state[2][1]], SBOX[state[2][2]], SBOX[state[2][3]]],
      [SBOX[state[3][0]], SBOX[state[3][1]], SBOX[state[3][2]], SBOX[state[3][3]]]
    ];
  }

  /**
   * InvSubBytes — thay thế qua Inverse S-Box
   */
  function invSubBytes(state) {
    const INV = Core.INV_SBOX;
    return [
      [INV[state[0][0]], INV[state[0][1]], INV[state[0][2]], INV[state[0][3]]],
      [INV[state[1][0]], INV[state[1][1]], INV[state[1][2]], INV[state[1][3]]],
      [INV[state[2][0]], INV[state[2][1]], INV[state[2][2]], INV[state[2][3]]],
      [INV[state[3][0]], INV[state[3][1]], INV[state[3][2]], INV[state[3][3]]]
    ];
  }

  /**
   * ShiftRows — dịch vòng trái các hàng
   */
  function shiftRows(state) {
    return [
      [state[0][0], state[0][1], state[0][2], state[0][3]],
      [state[1][1], state[1][2], state[1][3], state[1][0]],
      [state[2][2], state[2][3], state[2][0], state[2][1]],
      [state[3][3], state[3][0], state[3][1], state[3][2]]
    ];
  }

  /**
   * InvShiftRows — dịch vòng phải (nghịch đảo)
   */
  function invShiftRows(state) {
    return [
      [state[0][0], state[0][1], state[0][2], state[0][3]],
      [state[1][3], state[1][0], state[1][1], state[1][2]],
      [state[2][2], state[2][3], state[2][0], state[2][1]],
      [state[3][1], state[3][2], state[3][3], state[3][0]]
    ];
  }

  /**
   * MixColumns — nhân ma trận trong GF(2⁸)
   */
  function mixColumns(state) {
    const g = Core.gmul;
    const out = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]];
    for (let c = 0; c < 4; c++) {
      const s0 = state[0][c], s1 = state[1][c], s2 = state[2][c], s3 = state[3][c];
      out[0][c] = g(2, s0) ^ g(3, s1) ^ s2 ^ s3;
      out[1][c] = s0 ^ g(2, s1) ^ g(3, s2) ^ s3;
      out[2][c] = s0 ^ s1 ^ g(2, s2) ^ g(3, s3);
      out[3][c] = g(3, s0) ^ s1 ^ s2 ^ g(2, s3);
    }
    return out;
  }

  /**
   * InvMixColumns — nghịch đảo MixColumns
   */
  function invMixColumns(state) {
    const g = Core.gmul;
    const out = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]];
    for (let c = 0; c < 4; c++) {
      const s0 = state[0][c], s1 = state[1][c], s2 = state[2][c], s3 = state[3][c];
      out[0][c] = g(0x0e, s0) ^ g(0x0b, s1) ^ g(0x0d, s2) ^ g(0x09, s3);
      out[1][c] = g(0x09, s0) ^ g(0x0e, s1) ^ g(0x0b, s2) ^ g(0x0d, s3);
      out[2][c] = g(0x0d, s0) ^ g(0x09, s1) ^ g(0x0e, s2) ^ g(0x0b, s3);
      out[3][c] = g(0x0b, s0) ^ g(0x0d, s1) ^ g(0x09, s2) ^ g(0x0e, s3);
    }
    return out;
  }

  /**
   * AddRoundKey — XOR state với round key
   */
  function addRoundKey(state, w, round) {
    const out = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]];
    for (let c = 0; c < 4; c++)
      for (let r = 0; r < 4; r++)
        out[r][c] = state[r][c] ^ w[round * 4 + c][r];
    return out;
  }

  // ════════════════════════════════════════════
  //  PKCS#7 PADDING (forward từ logic core)
  // ════════════════════════════════════════════

  function pkcs7Pad(data) {
    const pad = 16 - (data.length % 16);
    const out = new Array(data.length + pad);
    for (let i = 0; i < data.length; i++) out[i] = data[i];
    for (let i = data.length; i < out.length; i++) out[i] = pad;
    return out;
  }

  function pkcs7Unpad(data) {
    if (data.length === 0) throw new Error('Dữ liệu rỗng, không thể unpad');
    const pad = data[data.length - 1];
    if (pad < 1 || pad > 16) throw new Error('Padding PKCS#7 không hợp lệ');
    for (let i = data.length - pad; i < data.length; i++) {
      if (data[i] !== pad) throw new Error('Padding PKCS#7 bị hỏng');
    }
    return data.slice(0, data.length - pad);
  }

  // ════════════════════════════════════════════
  //  ECB MODE — Electronic Codebook
  // ════════════════════════════════════════════

  /**
   * Mã hóa AES-ECB
   * Mỗi block 16 bytes được mã hóa độc lập
   * ⚠️ ECB không an toàn cho dữ liệu có pattern lặp!
   *
   * @param {number[]} plainBytes  - dữ liệu gốc
   * @param {number[]} keyBytes    - khóa (16/24/32 bytes)
   * @returns {number[]} ciphertext bytes
   */
  function aesECBEncrypt(plainBytes, keyBytes) {
    const ks = Core.keyExpansion(keyBytes);
    const padded = pkcs7Pad(plainBytes);
    const result = new Array(padded.length);

    for (let i = 0; i < padded.length; i += 16) {
      const block = padded.slice(i, i + 16);
      const enc = Core.aesEncryptBlock(block, ks);
      for (let j = 0; j < 16; j++) result[i + j] = enc[j];
    }
    return result;
  }

  /**
   * Giải mã AES-ECB
   * @param {number[]} cipherBytes - dữ liệu mã hóa
   * @param {number[]} keyBytes    - khóa (16/24/32 bytes)
   * @returns {number[]} plaintext bytes
   */
  function aesECBDecrypt(cipherBytes, keyBytes) {
    if (cipherBytes.length % 16 !== 0)
      throw new Error('Độ dài ciphertext phải là bội số của 16 (ECB)');

    const ks = Core.keyExpansion(keyBytes);
    const result = new Array(cipherBytes.length);

    for (let i = 0; i < cipherBytes.length; i += 16) {
      const block = cipherBytes.slice(i, i + 16);
      const dec = Core.aesDecryptBlock(block, ks);
      for (let j = 0; j < 16; j++) result[i + j] = dec[j];
    }
    return pkcs7Unpad(result);
  }

  // ════════════════════════════════════════════
  //  CTR MODE — Counter
  // ════════════════════════════════════════════

  /**
   * Tăng counter block (big-endian) — tự cài đặt
   * Counter chiếm 8 bytes cuối cùng của block 16 bytes
   * Tăng từ byte cuối cùng (byte[15]) ngược về byte[8]
   *
   * @param {number[]} counterBlock - mảng 16 bytes [nonce(8) || counter(8)]
   * @returns {number[]} counter block mới (đã tăng 1)
   */
  function incrementCounter(counterBlock) {
    const out = new Array(16);
    for (let i = 0; i < 16; i++) out[i] = counterBlock[i];

    // Tăng 8 bytes cuối (big-endian)
    for (let i = 15; i >= 8; i--) {
      out[i] = (out[i] + 1) & 0xFF;
      if (out[i] !== 0) break;  // không tràn → dừng
    }
    return out;
  }

  /**
   * Mã hóa AES-CTR
   * CTR là stream cipher: encrypt counter → XOR với plaintext
   * Không cần padding!
   *
   * @param {number[]} plainBytes - dữ liệu gốc
   * @param {number[]} keyBytes   - khóa (16/24/32 bytes)
   * @param {number[]} nonce      - nonce 8 bytes
   * @returns {number[]} ciphertext bytes (cùng độ dài với plaintext)
   */
  function aesCTREncrypt(plainBytes, keyBytes, nonce) {
    if (!nonce || nonce.length !== 8)
      throw new Error('CTR mode cần nonce đúng 8 bytes');

    const ks = Core.keyExpansion(keyBytes);
    const result = new Array(plainBytes.length);

    // Xây dựng counter block ban đầu: nonce(8) || 0x0000000000000000(8)
    var counterBlock = [
      nonce[0], nonce[1], nonce[2], nonce[3],
      nonce[4], nonce[5], nonce[6], nonce[7],
      0, 0, 0, 0, 0, 0, 0, 0
    ];

    for (let i = 0; i < plainBytes.length; i += 16) {
      // Mã hóa counter block
      const keystream = Core.aesEncryptBlock(counterBlock, ks);

      // XOR keystream với plaintext block
      const remaining = plainBytes.length - i;
      const blockLen = remaining < 16 ? remaining : 16;
      for (let j = 0; j < blockLen; j++) {
        result[i + j] = plainBytes[i + j] ^ keystream[j];
      }

      // Tăng counter
      counterBlock = incrementCounter(counterBlock);
    }
    return result;
  }

  /**
   * Giải mã AES-CTR
   * CTR decryption = CTR encryption (đối xứng)
   */
  function aesCTRDecrypt(cipherBytes, keyBytes, nonce) {
    return aesCTREncrypt(cipherBytes, keyBytes, nonce);
  }

  // ════════════════════════════════════════════
  //  CFB MODE — Cipher Feedback
  // ════════════════════════════════════════════

  /**
   * Mã hóa AES-CFB (segment size = 128 bit = full block)
   * Mỗi bước: mã hóa shift register → XOR với plaintext block → kết quả
   * vừa là ciphertext, vừa trở thành shift register mới.
   * Không cần padding (stream cipher).
   *
   * @param {number[]} plainBytes - dữ liệu gốc (bất kỳ độ dài)
   * @param {number[]} keyBytes   - khóa (16/24/32 bytes)
   * @param {number[]} iv         - IV 16 bytes
   * @returns {number[]} ciphertext bytes (cùng độ dài với plaintext)
   */
  function aesCFBEncrypt(plainBytes, keyBytes, iv) {
    if (!iv || iv.length !== 16)
      throw new Error('CFB mode cần IV đúng 16 bytes');

    var ks = Core.keyExpansion(keyBytes);
    var result = new Array(plainBytes.length);
    var shiftReg = iv.slice();

    for (var i = 0; i < plainBytes.length; i += 16) {
      var encReg = Core.aesEncryptBlock(shiftReg, ks);
      var remaining = plainBytes.length - i;
      var blockLen = remaining < 16 ? remaining : 16;

      // Tạo block ciphertext mới cho shift register
      var newShift = new Array(16);
      for (var j = 0; j < 16; j++) newShift[j] = 0;

      for (var j = 0; j < blockLen; j++) {
        result[i + j] = plainBytes[i + j] ^ encReg[j];
        newShift[j] = result[i + j];
      }
      // Nếu block cuối < 16 bytes, pad shift register bằng 0
      shiftReg = newShift;
    }
    return result;
  }

  /**
   * Giải mã AES-CFB
   *
   * @param {number[]} cipherBytes - dữ liệu đã mã hóa
   * @param {number[]} keyBytes    - khóa (16/24/32 bytes)
   * @param {number[]} iv          - IV 16 bytes
   * @returns {number[]} plaintext bytes
   */
  function aesCFBDecrypt(cipherBytes, keyBytes, iv) {
    if (!iv || iv.length !== 16)
      throw new Error('CFB mode cần IV đúng 16 bytes');

    var ks = Core.keyExpansion(keyBytes);
    var result = new Array(cipherBytes.length);
    var shiftReg = iv.slice();

    for (var i = 0; i < cipherBytes.length; i += 16) {
      var encReg = Core.aesEncryptBlock(shiftReg, ks);
      var remaining = cipherBytes.length - i;
      var blockLen = remaining < 16 ? remaining : 16;

      // Tạo shift register mới từ ciphertext TRƯỚC khi XOR
      var newShift = new Array(16);
      for (var j = 0; j < 16; j++) newShift[j] = 0;
      for (var j = 0; j < blockLen; j++) newShift[j] = cipherBytes[i + j];

      for (var j = 0; j < blockLen; j++) {
        result[i + j] = cipherBytes[i + j] ^ encReg[j];
      }
      shiftReg = newShift;
    }
    return result;
  }

  // ════════════════════════════════════════════
  //  OFB MODE — Output Feedback
  // ════════════════════════════════════════════

  /**
   * Mã hóa AES-OFB
   * Mỗi bước: mã hóa feedback block → output = XOR với plaintext.
   * Feedback block = kết quả mã hóa (KHÔNG phải ciphertext).
   * Encrypt = Decrypt (đối xứng hoàn toàn).
   * Không cần padding (stream cipher).
   *
   * @param {number[]} plainBytes - dữ liệu gốc (bất kỳ độ dài)
   * @param {number[]} keyBytes   - khóa (16/24/32 bytes)
   * @param {number[]} iv         - IV 16 bytes
   * @returns {number[]} ciphertext bytes (cùng độ dài với plaintext)
   */
  function aesOFBEncrypt(plainBytes, keyBytes, iv) {
    if (!iv || iv.length !== 16)
      throw new Error('OFB mode cần IV đúng 16 bytes');

    var ks = Core.keyExpansion(keyBytes);
    var result = new Array(plainBytes.length);
    var feedback = iv.slice();

    for (var i = 0; i < plainBytes.length; i += 16) {
      // Mã hóa feedback block → tạo keystream
      feedback = Core.aesEncryptBlock(feedback, ks);

      var remaining = plainBytes.length - i;
      var blockLen = remaining < 16 ? remaining : 16;
      for (var j = 0; j < blockLen; j++) {
        result[i + j] = plainBytes[i + j] ^ feedback[j];
      }
    }
    return result;
  }

  /**
   * Giải mã AES-OFB
   * OFB decryption = OFB encryption (đối xứng hoàn toàn)
   */
  function aesOFBDecrypt(cipherBytes, keyBytes, iv) {
    return aesOFBEncrypt(cipherBytes, keyBytes, iv);
  }

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
      return aesECBEncrypt(plainBytes, keyBytes);
    }
    if (mode === 'cbc') {
      var iv = opts && opts.iv;
      if (!iv) throw new Error('CBC mode cần IV 16 bytes');
      return Core.aesCBCEncrypt(plainBytes, keyBytes, iv);
    }
    if (mode === 'cfb') {
      var iv = opts && opts.iv;
      if (!iv) throw new Error('CFB mode cần IV 16 bytes');
      return aesCFBEncrypt(plainBytes, keyBytes, iv);
    }
    if (mode === 'ofb') {
      var iv = opts && opts.iv;
      if (!iv) throw new Error('OFB mode cần IV 16 bytes');
      return aesOFBEncrypt(plainBytes, keyBytes, iv);
    }
    if (mode === 'ctr') {
      var nonce = opts && opts.nonce;
      if (!nonce) throw new Error('CTR mode cần nonce 8 bytes');
      return aesCTREncrypt(plainBytes, keyBytes, nonce);
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
      return aesECBDecrypt(cipherBytes, keyBytes);
    }
    if (mode === 'cbc') {
      var iv = opts && opts.iv;
      if (!iv) throw new Error('CBC mode cần IV 16 bytes');
      return Core.aesCBCDecrypt(cipherBytes, keyBytes, iv);
    }
    if (mode === 'cfb') {
      var iv = opts && opts.iv;
      if (!iv) throw new Error('CFB mode cần IV 16 bytes');
      return aesCFBDecrypt(cipherBytes, keyBytes, iv);
    }
    if (mode === 'ofb') {
      var iv = opts && opts.iv;
      if (!iv) throw new Error('OFB mode cần IV 16 bytes');
      return aesOFBDecrypt(cipherBytes, keyBytes, iv);
    }
    if (mode === 'ctr') {
      var nonce = opts && opts.nonce;
      if (!nonce) throw new Error('CTR mode cần nonce 8 bytes');
      return aesCTRDecrypt(cipherBytes, keyBytes, nonce);
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
      var cipher = aesECBEncrypt(plainBytes, keyBytes);
      result.cipher = U.toBase64(cipher);
    } else if (mode === 'cbc') {
      var iv = (opts && opts.iv) ? opts.iv : U.randomBytes(16);
      var cipher = Core.aesCBCEncrypt(plainBytes, keyBytes, iv);
      result.cipher = U.toBase64(cipher);
      result.iv = U.toBase64(iv);
    } else if (mode === 'cfb') {
      var iv = (opts && opts.iv) ? opts.iv : U.randomBytes(16);
      var cipher = aesCFBEncrypt(plainBytes, keyBytes, iv);
      result.cipher = U.toBase64(cipher);
      result.iv = U.toBase64(iv);
    } else if (mode === 'ofb') {
      var iv = (opts && opts.iv) ? opts.iv : U.randomBytes(16);
      var cipher = aesOFBEncrypt(plainBytes, keyBytes, iv);
      result.cipher = U.toBase64(cipher);
      result.iv = U.toBase64(iv);
    } else if (mode === 'ctr') {
      var nonce = (opts && opts.nonce) ? opts.nonce : U.randomBytes(8);
      var cipher = aesCTREncrypt(plainBytes, keyBytes, nonce);
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
      plainBytes = aesECBDecrypt(cipherBytes, keyBytes);
    } else if (mode === 'cbc') {
      var iv = opts && opts.ivB64 ? U.fromBase64(opts.ivB64) : null;
      if (!iv) throw new Error('CBC giải mã cần IV (Base64)');
      plainBytes = Core.aesCBCDecrypt(cipherBytes, keyBytes, iv);
    } else if (mode === 'cfb') {
      var iv = opts && opts.ivB64 ? U.fromBase64(opts.ivB64) : null;
      if (!iv) throw new Error('CFB giải mã cần IV (Base64)');
      plainBytes = aesCFBDecrypt(cipherBytes, keyBytes, iv);
    } else if (mode === 'ofb') {
      var iv = opts && opts.ivB64 ? U.fromBase64(opts.ivB64) : null;
      if (!iv) throw new Error('OFB giải mã cần IV (Base64)');
      plainBytes = aesOFBDecrypt(cipherBytes, keyBytes, iv);
    } else if (mode === 'ctr') {
      var nonce = opts && opts.nonceB64 ? U.fromBase64(opts.nonceB64) : null;
      if (!nonce) throw new Error('CTR giải mã cần Nonce (Base64)');
      plainBytes = aesCTRDecrypt(cipherBytes, keyBytes, nonce);
    } else {
      throw new Error('Mode không hợp lệ: ' + mode);
    }
    return U.bytesToStr(plainBytes);
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

    var state = bytesToState(block);
    capture(state, 0, 'Initial State', 'none');

    state = addRoundKey(state, w, 0);
    capture(state, 0, 'AddRoundKey[0]', 'ark');

    for (var round = 1; round < Nr; round++) {
      state = subBytes(state);
      capture(state, round, 'R' + round + ': SubBytes', 'sub');
      state = shiftRows(state);
      capture(state, round, 'R' + round + ': ShiftRows', 'shift');
      state = mixColumns(state);
      capture(state, round, 'R' + round + ': MixColumns', 'mix');
      state = addRoundKey(state, w, round);
      capture(state, round, 'R' + round + ': AddRoundKey', 'ark');
    }

    // Vòng cuối
    state = subBytes(state);
    capture(state, Nr, 'R' + Nr + ': SubBytes', 'sub');
    state = shiftRows(state);
    capture(state, Nr, 'R' + Nr + ': ShiftRows (Final)', 'shift');
    state = addRoundKey(state, w, Nr);
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

    var state = bytesToState(block);
    capture(state, Nr, 'Initial Ciphertext', 'none');

    state = addRoundKey(state, w, Nr);
    capture(state, Nr, 'AddRoundKey[' + Nr + ']', 'ark');

    for (var round = Nr - 1; round >= 1; round--) {
      state = invShiftRows(state);
      capture(state, round, 'R' + round + ': InvShiftRows', 'shift');
      state = invSubBytes(state);
      capture(state, round, 'R' + round + ': InvSubBytes', 'sub');
      state = addRoundKey(state, w, round);
      capture(state, round, 'R' + round + ': AddRoundKey', 'ark');
      state = invMixColumns(state);
      capture(state, round, 'R' + round + ': InvMixColumns', 'mix');
    }

    // Vòng cuối
    state = invShiftRows(state);
    capture(state, 0, 'R0: InvShiftRows', 'shift');
    state = invSubBytes(state);
    capture(state, 0, 'R0: InvSubBytes', 'sub');
    state = addRoundKey(state, w, 0);
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

    // ── Low-level mode functions
    ecbEncrypt: aesECBEncrypt,
    ecbDecrypt: aesECBDecrypt,
    cbcEncrypt: Core.aesCBCEncrypt,
    cbcDecrypt: Core.aesCBCDecrypt,
    cfbEncrypt: aesCFBEncrypt,
    cfbDecrypt: aesCFBDecrypt,
    ofbEncrypt: aesOFBEncrypt,
    ofbDecrypt: aesOFBDecrypt,
    ctrEncrypt: aesCTREncrypt,
    ctrDecrypt: aesCTRDecrypt,

    // ── Block-level
    encryptBlock: Core.aesEncryptBlock,
    decryptBlock: Core.aesDecryptBlock,
    keyExpansion: Core.keyExpansion,

    // ── Internal transforms (cho visualizer)
    internal: {
      bytesToState: bytesToState,
      stateToBytes: stateToBytes,
      subBytes: subBytes,
      invSubBytes: invSubBytes,
      shiftRows: shiftRows,
      invShiftRows: invShiftRows,
      mixColumns: mixColumns,
      invMixColumns: invMixColumns,
      addRoundKey: addRoundKey,
      keyExpansion: Core.keyExpansion,
      SBOX: Core.SBOX,
      INV_SBOX: Core.INV_SBOX,
      gmul: Core.gmul,
      pkcs7Pad: pkcs7Pad,
      pkcs7Unpad: pkcs7Unpad,
      incrementCounter: incrementCounter
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
      prepareKey: U.prepareKey,
      validateInputs: U.validateInputs,
      formatHexDump: U.formatHexDump
    },

    // ── Mode info
    modes: modes
  };

})();
