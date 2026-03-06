/**
 * utils.js
 * ============================================================
 * Các hàm tiện ích tự cài đặt:
 *  - UTF-8 encode / decode
 *  - Base64 encode / decode (không dùng btoa/atob)
 *  - Hex encode / decode
 *  - Random bytes (không dùng crypto API)
 *  - Key preparation / validation
 * ============================================================
 */

// ─────────────────────────────────────────────
//  UTF-8 ENCODE / DECODE
// ─────────────────────────────────────────────

/**
 * Chuyển chuỗi JavaScript (UTF-16) sang mảng bytes UTF-8
 * Tự cài đặt — không dùng TextEncoder
 * @param {string} str
 * @returns {number[]}
 */
function strToBytes(str) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);

    // Xử lý surrogate pairs (emoji, ký tự ngoài BMP)
    if (code >= 0xD800 && code <= 0xDBFF) {
      const hi = code;
      const lo = str.charCodeAt(++i);
      code = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
    }

    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xC0 | (code >> 6));
      bytes.push(0x80 | (code & 0x3F));
    } else if (code < 0x10000) {
      bytes.push(0xE0 | (code >> 12));
      bytes.push(0x80 | ((code >> 6) & 0x3F));
      bytes.push(0x80 | (code & 0x3F));
    } else {
      bytes.push(0xF0 | (code >> 18));
      bytes.push(0x80 | ((code >> 12) & 0x3F));
      bytes.push(0x80 | ((code >> 6) & 0x3F));
      bytes.push(0x80 | (code & 0x3F));
    }
  }
  return bytes;
}

/**
 * Chuyển mảng bytes UTF-8 về chuỗi JavaScript
 * Tự cài đặt — không dùng TextDecoder
 * @param {number[]} bytes
 * @returns {string}
 */
function bytesToStr(bytes) {
  let str = '';
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i];
    let codePoint;

    if ((b0 & 0x80) === 0) {
      codePoint = b0; i += 1;
    } else if ((b0 & 0xE0) === 0xC0) {
      codePoint = ((b0 & 0x1F) << 6) | (bytes[i+1] & 0x3F);
      i += 2;
    } else if ((b0 & 0xF0) === 0xE0) {
      codePoint = ((b0 & 0x0F) << 12) | ((bytes[i+1] & 0x3F) << 6) | (bytes[i+2] & 0x3F);
      i += 3;
    } else {
      codePoint = ((b0 & 0x07) << 18) | ((bytes[i+1] & 0x3F) << 12) |
                  ((bytes[i+2] & 0x3F) << 6) | (bytes[i+3] & 0x3F);
      i += 4;
    }

    if (codePoint < 0x10000) {
      str += String.fromCharCode(codePoint);
    } else {
      // Encode as surrogate pair
      codePoint -= 0x10000;
      str += String.fromCharCode(0xD800 + (codePoint >> 10));
      str += String.fromCharCode(0xDC00 + (codePoint & 0x3FF));
    }
  }
  return str;
}

// ─────────────────────────────────────────────
//  BASE64 ENCODE / DECODE (không dùng btoa/atob)
// ─────────────────────────────────────────────

const _B64_TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const _B64_LOOKUP = {};
for (let i = 0; i < _B64_TABLE.length; i++) _B64_LOOKUP[_B64_TABLE[i]] = i;

/**
 * Mã hóa mảng bytes sang chuỗi Base64
 * @param {number[]} bytes
 * @returns {string}
 */
function toBase64(bytes) {
  let result = '';
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = (i + 1 < len) ? bytes[i + 1] : 0;
    const b2 = (i + 2 < len) ? bytes[i + 2] : 0;

    result += _B64_TABLE[b0 >> 2];
    result += _B64_TABLE[((b0 & 0x03) << 4) | (b1 >> 4)];
    result += (i + 1 < len) ? _B64_TABLE[((b1 & 0x0F) << 2) | (b2 >> 6)] : '=';
    result += (i + 2 < len) ? _B64_TABLE[b2 & 0x3F] : '=';
  }
  return result;
}

/**
 * Giải mã chuỗi Base64 về mảng bytes
 * @param {string} b64
 * @returns {number[]}
 */
function fromBase64(b64) {
  const clean = b64.replace(/\s/g, '');
  const bytes = [];
  const len = clean.length;

  for (let i = 0; i < len; i += 4) {
    const c0 = _B64_LOOKUP[clean[i]]     ?? 0;
    const c1 = _B64_LOOKUP[clean[i + 1]] ?? 0;
    const c2 = _B64_LOOKUP[clean[i + 2]] ?? 0;
    const c3 = _B64_LOOKUP[clean[i + 3]] ?? 0;

    bytes.push((c0 << 2) | (c1 >> 4));
    if (clean[i + 2] !== '=') bytes.push(((c1 & 0x0F) << 4) | (c2 >> 2));
    if (clean[i + 3] !== '=') bytes.push(((c2 & 0x03) << 6) | c3);
  }
  return bytes;
}

// ─────────────────────────────────────────────
//  HEX ENCODE / DECODE
// ─────────────────────────────────────────────

/**
 * Chuyển mảng bytes sang chuỗi hex (chữ hoa)
 */
function toHex(bytes) {
  return bytes.map(b => {
    const h = b.toString(16);
    return h.length === 1 ? '0' + h : h;
  }).join('').toUpperCase();
}

/**
 * Chuyển chuỗi hex sang mảng bytes
 */
function fromHex(hex) {
  const clean = hex.replace(/\s/g, '').toLowerCase();
  if (clean.length % 2 !== 0) throw new Error('Hex string phải có độ dài chẵn');
  const bytes = [];
  for (let i = 0; i < clean.length; i += 2) {
    const val = parseInt(clean[i] + clean[i+1], 16);
    if (isNaN(val)) throw new Error(`Ký tự hex không hợp lệ: ${clean[i]}${clean[i+1]}`);
    bytes.push(val);
  }
  return bytes;
}

// ─────────────────────────────────────────────
//  RANDOM BYTES (không dùng crypto.getRandomValues)
// ─────────────────────────────────────────────

/**
 * Sinh n bytes ngẫu nhiên dùng Math.random()
 * Kết hợp nhiều nguồn entropy: timestamp, Math.random, XOR chéo
 * @param {number} n - số bytes cần sinh
 * @returns {number[]}
 */
function randomBytes(n) {
  const result = [];
  let seed = (Date.now() ^ (Math.random() * 0xFFFFFFFF)) >>> 0;

  // Thuật toán xorshift32 đơn giản
  function xorshift() {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) & 0xFF;
  }

  for (let i = 0; i < n; i++) {
    // Kết hợp với Math.random để tăng entropy
    const r = xorshift() ^ ((Math.random() * 256) | 0);
    result.push(r & 0xFF);
  }
  return result;
}

// ─────────────────────────────────────────────
//  KEY PREPARATION & VALIDATION
// ─────────────────────────────────────────────

/**
 * Chuẩn bị khóa từ chuỗi text sang mảng bytes đúng kích thước
 * Pad bằng 0x00 nếu thiếu, cắt nếu thừa
 * @param {string} keyStr  - chuỗi khóa nhập vào
 * @param {number} keyBits - 128, 192, hoặc 256
 * @returns {number[]}
 */
function prepareKey(keyStr, keyBits) {
  const needed = keyBits / 8;
  let bytes = strToBytes(keyStr);
  // Pad bằng zeros nếu thiếu
  while (bytes.length < needed) bytes.push(0);
  return bytes.slice(0, needed);
}

/**
 * Validate thông tin đầu vào
 * @returns {{ valid: boolean, errors: string[] }}
 */
function validateInputs({ key, keyBits, plaintext, iv, mode }) {
  const errors = [];
  if (!key || key.trim() === '') errors.push('Khóa bí mật không được để trống');
  if (![128, 192, 256].includes(keyBits)) errors.push('Kích thước khóa không hợp lệ');
  if (mode === 'encrypt' && (!plaintext || plaintext.trim() === ''))
    errors.push('Văn bản cần mã hóa không được để trống');
  if (mode === 'decrypt' && (!plaintext || plaintext.trim() === ''))
    errors.push('Chuỗi mã hóa không được để trống');
  if (iv && strToBytes(iv).length > 16)
    errors.push('IV quá dài (tối đa 16 bytes)');
  return { valid: errors.length === 0, errors };
}

/**
 * Format bytes thành nhóm hex dễ đọc
 * @param {number[]} bytes
 * @param {number} groupSize - số bytes mỗi nhóm
 */
function formatHexDump(bytes, groupSize = 16) {
  const lines = [];
  for (let i = 0; i < bytes.length; i += groupSize) {
    const chunk = bytes.slice(i, i + groupSize);
    const offset = i.toString(16).padStart(4, '0').toUpperCase();
    const hex = chunk.map(b => b.toString(16).padStart(2,'0').toUpperCase()).join(' ');
    lines.push(`${offset}  ${hex.padEnd(groupSize * 3 - 1)}`);
  }
  return lines.join('\n');
}

// Export
window.Utils = {
  strToBytes,
  bytesToStr,
  toBase64,
  fromBase64,
  toHex,
  fromHex,
  randomBytes,
  prepareKey,
  validateInputs,
  formatHexDump
};
