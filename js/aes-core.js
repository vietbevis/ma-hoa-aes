/**
 * aes-core.js
 * ============================================================
 * Cài đặt thuật toán AES (Advanced Encryption Standard) từ đầu
 * Không sử dụng bất kỳ thư viện mã hóa nào của ngôn ngữ
 *
 * Hỗ trợ: AES-128, AES-192, AES-256
 * Mode:   CBC (Cipher Block Chaining)
 * Padding: PKCS#7
 *
 * Tác giả: Nguyễn Văn Việt, Trần Duy Quyến
 * Học viện Kỹ thuật Mật mã — Môn CSATBMTT
 * ============================================================
 */

// ─────────────────────────────────────────────
//  BẢNG HẰNG SỐ AES
// ─────────────────────────────────────────────

/**
 * S-Box: Bảng thay thế phi tuyến 8-bit
 * Được xây dựng từ nghịch đảo GF(2^8) + biến đổi affine
 */
const SBOX = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

/**
 * Inverse S-Box: Nghịch đảo của S-Box, dùng cho giải mã
 */
const INV_SBOX = new Array(256);
(function buildInvSbox() {
  for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;
})();

/**
 * Round Constants (Rcon): Hằng số vòng cho Key Expansion
 * Rcon[i] = x^(i-1) mod p(x) trong GF(2^8)
 */
const RCON = [
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
  0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
  0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97
];

// ─────────────────────────────────────────────
//  PHÉP TOÁN TRÊN GF(2^8)
// ─────────────────────────────────────────────

/**
 * Nhân hai số trong GF(2^8) — trường Galois
 * Đa thức bất khả quy: x^8 + x^4 + x^3 + x + 1 = 0x11b
 * @param {number} a - byte thứ nhất
 * @param {number} b - byte thứ hai
 * @returns {number} tích trong GF(2^8)
 */
function gmul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hiBit = a & 0x80;
    a = (a << 1) & 0xFF;
    if (hiBit) a ^= 0x1b; // XOR với đa thức x^8+x^4+x^3+x+1 (bỏ bit x^8)
    b >>= 1;
  }
  return p;
}

// ─────────────────────────────────────────────
//  KEY EXPANSION (MỞ RỘNG KHÓA)
// ─────────────────────────────────────────────

/**
 * Mở rộng khóa AES thành các round keys
 * @param {number[]} key - mảng byte của khóa (16, 24, hoặc 32 bytes)
 * @returns {{ w: number[][], nr: number }} - schedule và số vòng
 */
function keyExpansion(key) {
  const Nk = key.length / 4;  // Số word trong khóa: 4 / 6 / 8
  const Nr = Nk + 6;          // Số vòng: 10 / 12 / 14
  const totalWords = (Nr + 1) * 4;

  // Khởi tạo Nk word đầu tiên từ khóa gốc
  const w = [];
  for (let i = 0; i < Nk; i++) {
    w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
  }

  for (let i = Nk; i < totalWords; i++) {
    let temp = [...w[i - 1]];

    if (i % Nk === 0) {
      // RotWord: xoay trái 1 byte
      temp = [temp[1], temp[2], temp[3], temp[0]];
      // SubWord: áp dụng S-Box
      temp = temp.map(b => SBOX[b]);
      // XOR với Rcon
      temp[0] ^= RCON[i / Nk];
    } else if (Nk > 6 && i % Nk === 4) {
      // Chỉ áp dụng SubWord cho AES-256
      temp = temp.map(b => SBOX[b]);
    }

    w[i] = w[i - Nk].map((b, j) => b ^ temp[j]);
  }

  return { w, Nr };
}

// ─────────────────────────────────────────────
//  CÁC PHÉP BIẾN ĐỔI STATE (4×4 BYTES)
// ─────────────────────────────────────────────

/**
 * SubBytes: Thay thế từng byte qua S-Box
 */
function subBytes(state) {
  return state.map(row => row.map(b => SBOX[b]));
}

/**
 * InvSubBytes: Thay thế ngược qua Inverse S-Box
 */
function invSubBytes(state) {
  return state.map(row => row.map(b => INV_SBOX[b]));
}

/**
 * ShiftRows: Dịch vòng các hàng của state
 * Hàng 0: không dịch
 * Hàng 1: dịch trái 1
 * Hàng 2: dịch trái 2
 * Hàng 3: dịch trái 3
 */
function shiftRows(state) {
  return [
    [...state[0]],
    [state[1][1], state[1][2], state[1][3], state[1][0]],
    [state[2][2], state[2][3], state[2][0], state[2][1]],
    [state[3][3], state[3][0], state[3][1], state[3][2]]
  ];
}

/**
 * InvShiftRows: Dịch vòng phải (nghịch đảo)
 */
function invShiftRows(state) {
  return [
    [...state[0]],
    [state[1][3], state[1][0], state[1][1], state[1][2]],
    [state[2][2], state[2][3], state[2][0], state[2][1]],
    [state[3][1], state[3][2], state[3][3], state[3][0]]
  ];
}

/**
 * MixColumns: Trộn các cột trong GF(2^8)
 * Ma trận nhân:
 * [ 2  3  1  1 ]
 * [ 1  2  3  1 ]
 * [ 1  1  2  3 ]
 * [ 3  1  1  2 ]
 */
function mixColumns(state) {
  const out = Array.from({ length: 4 }, () => new Array(4).fill(0));
  for (let c = 0; c < 4; c++) {
    const s = [state[0][c], state[1][c], state[2][c], state[3][c]];
    out[0][c] = gmul(2, s[0]) ^ gmul(3, s[1]) ^ s[2] ^ s[3];
    out[1][c] = s[0] ^ gmul(2, s[1]) ^ gmul(3, s[2]) ^ s[3];
    out[2][c] = s[0] ^ s[1] ^ gmul(2, s[2]) ^ gmul(3, s[3]);
    out[3][c] = gmul(3, s[0]) ^ s[1] ^ s[2] ^ gmul(2, s[3]);
  }
  return out;
}

/**
 * InvMixColumns: Nghịch đảo MixColumns
 * Ma trận nhân:
 * [ 0x0e  0x0b  0x0d  0x09 ]
 * [ 0x09  0x0e  0x0b  0x0d ]
 * [ 0x0d  0x09  0x0e  0x0b ]
 * [ 0x0b  0x0d  0x09  0x0e ]
 */
function invMixColumns(state) {
  const out = Array.from({ length: 4 }, () => new Array(4).fill(0));
  for (let c = 0; c < 4; c++) {
    const s = [state[0][c], state[1][c], state[2][c], state[3][c]];
    out[0][c] = gmul(0x0e, s[0]) ^ gmul(0x0b, s[1]) ^ gmul(0x0d, s[2]) ^ gmul(0x09, s[3]);
    out[1][c] = gmul(0x09, s[0]) ^ gmul(0x0e, s[1]) ^ gmul(0x0b, s[2]) ^ gmul(0x0d, s[3]);
    out[2][c] = gmul(0x0d, s[0]) ^ gmul(0x09, s[1]) ^ gmul(0x0e, s[2]) ^ gmul(0x0b, s[3]);
    out[3][c] = gmul(0x0b, s[0]) ^ gmul(0x0d, s[1]) ^ gmul(0x09, s[2]) ^ gmul(0x0e, s[3]);
  }
  return out;
}

/**
 * AddRoundKey: XOR state với round key tương ứng
 */
function addRoundKey(state, w, round) {
  const out = Array.from({ length: 4 }, () => new Array(4).fill(0));
  for (let c = 0; c < 4; c++)
    for (let r = 0; r < 4; r++)
      out[r][c] = state[r][c] ^ w[round * 4 + c][r];
  return out;
}

// ─────────────────────────────────────────────
//  CHUYỂN ĐỔI BLOCK ↔ STATE
// ─────────────────────────────────────────────

/**
 * Chuyển 16 bytes sang ma trận state 4×4 (column-major)
 */
function bytesToState(block) {
  const state = Array.from({ length: 4 }, () => new Array(4).fill(0));
  for (let r = 0; r < 4; r++)
    for (let c = 0; c < 4; c++)
      state[r][c] = block[r + 4 * c];
  return state;
}

/**
 * Chuyển ma trận state 4×4 sang 16 bytes
 */
function stateToBytes(state) {
  const block = new Array(16);
  for (let r = 0; r < 4; r++)
    for (let c = 0; c < 4; c++)
      block[r + 4 * c] = state[r][c];
  return block;
}

// ─────────────────────────────────────────────
//  MÃ HÓA / GIẢI MÃ 1 BLOCK (16 BYTES)
// ─────────────────────────────────────────────

/**
 * Mã hóa một block 16 bytes bằng AES
 * @param {number[]} block - 16 bytes plaintext
 * @param {{ w, Nr }} ks - key schedule
 * @returns {number[]} 16 bytes ciphertext
 */
function aesEncryptBlock(block, ks) {
  const { w, Nr } = ks;
  let state = bytesToState(block);
  state = addRoundKey(state, w, 0);

  for (let round = 1; round < Nr; round++) {
    state = subBytes(state);
    state = shiftRows(state);
    state = mixColumns(state);
    state = addRoundKey(state, w, round);
  }

  // Vòng cuối: không có MixColumns
  state = subBytes(state);
  state = shiftRows(state);
  state = addRoundKey(state, w, Nr);

  return stateToBytes(state);
}

/**
 * Giải mã một block 16 bytes bằng AES
 * @param {number[]} block - 16 bytes ciphertext
 * @param {{ w, Nr }} ks - key schedule
 * @returns {number[]} 16 bytes plaintext
 */
function aesDecryptBlock(block, ks) {
  const { w, Nr } = ks;
  let state = bytesToState(block);
  state = addRoundKey(state, w, Nr);

  for (let round = Nr - 1; round >= 1; round--) {
    state = invShiftRows(state);
    state = invSubBytes(state);
    state = addRoundKey(state, w, round);
    state = invMixColumns(state);
  }

  state = invShiftRows(state);
  state = invSubBytes(state);
  state = addRoundKey(state, w, 0);

  return stateToBytes(state);
}

// ─────────────────────────────────────────────
//  PKCS#7 PADDING
// ─────────────────────────────────────────────

/**
 * Thêm padding PKCS#7 để dữ liệu chia hết cho 16 bytes
 */
function pkcs7Pad(data) {
  const pad = 16 - (data.length % 16);
  const out = [...data];
  for (let i = 0; i < pad; i++) out.push(pad);
  return out;
}

/**
 * Loại bỏ padding PKCS#7
 * @throws {Error} nếu padding không hợp lệ
 */
function pkcs7Unpad(data) {
  const pad = data[data.length - 1];
  if (pad < 1 || pad > 16) throw new Error('Padding PKCS#7 không hợp lệ');
  for (let i = data.length - pad; i < data.length; i++) {
    if (data[i] !== pad) throw new Error('Padding PKCS#7 bị hỏng');
  }
  return data.slice(0, data.length - pad);
}

// ─────────────────────────────────────────────
//  CBC MODE (CIPHER BLOCK CHAINING)
// ─────────────────────────────────────────────

/**
 * Mã hóa AES-CBC
 * @param {number[]} plainBytes  - dữ liệu gốc (bytes)
 * @param {number[]} keyBytes    - khóa (16/24/32 bytes)
 * @param {number[]} ivBytes     - IV (16 bytes)
 * @returns {number[]} ciphertext bytes
 */
function aesCBCEncrypt(plainBytes, keyBytes, ivBytes) {
  const ks = keyExpansion(keyBytes);
  const padded = pkcs7Pad(plainBytes);
  const result = [];
  let prev = [...ivBytes];

  for (let i = 0; i < padded.length; i += 16) {
    const block = padded.slice(i, i + 16);
    // XOR với block trước (CBC)
    const xored = block.map((b, j) => b ^ prev[j]);
    const enc = aesEncryptBlock(xored, ks);
    result.push(...enc);
    prev = enc;
  }
  return result;
}

/**
 * Giải mã AES-CBC
 * @param {number[]} cipherBytes - dữ liệu mã hóa (bytes)
 * @param {number[]} keyBytes    - khóa (16/24/32 bytes)
 * @param {number[]} ivBytes     - IV (16 bytes)
 * @returns {number[]} plaintext bytes
 */
function aesCBCDecrypt(cipherBytes, keyBytes, ivBytes) {
  if (cipherBytes.length % 16 !== 0)
    throw new Error('Độ dài ciphertext phải là bội số của 16');

  const ks = keyExpansion(keyBytes);
  const result = [];
  let prev = [...ivBytes];

  for (let i = 0; i < cipherBytes.length; i += 16) {
    const block = cipherBytes.slice(i, i + 16);
    const dec = aesDecryptBlock(block, ks);
    const xored = dec.map((b, j) => b ^ prev[j]);
    result.push(...xored);
    prev = block;
  }
  return pkcs7Unpad(result);
}

// Export cho các module khác
window.AESCore = {
  aesCBCEncrypt,
  aesCBCDecrypt,
  keyExpansion,
  aesEncryptBlock,
  aesDecryptBlock,
  SBOX,
  INV_SBOX,
  gmul
};
