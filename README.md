# AES Cipher — Cơ sở an toàn và bảo mật thông tin

> **Học viện Kỹ thuật Mật mã** — Môn Cơ sở an toàn và bảo mật thông tin  
> Cài đặt thuật toán **Advanced Encryption Standard (AES)** từ đầu bằng JavaScript thuần túy  
> Không sử dụng bất kỳ hàm hay thư viện mã hóa có sẵn nào.
>
> **Thành viên:** Nguyễn Văn Việt (CT070262), Trần Duy Quyến (CT070245)

---

## 📁 Cấu trúc thư mục

```
aes-project/
├── index.html              # Trang chủ & giới thiệu
├── README.md               # Tài liệu này
├── css/
│   └── style.css           # Stylesheet chung cho toàn dự án
├── js/
│   ├── aes-core.js         # Lõi AES: GF(2⁸), Key Expansion, 4 phép biến đổi, CBC
│   ├── aes-lib.js          # Thư viện wrapper: ECB, CBC, CFB, OFB, CTR mode
│   ├── utils.js            # UTF-8, Base64, Hex, PKCS#7, random bytes
│   └── tests.js            # Bộ test NIST FIPS 197 / RFC 3602 / round-trip
├── pages/
│   ├── theory.html         # Giải thích lý thuyết AES đầy đủ
│   ├── demo.html           # Demo mã hóa / giải mã tương tác
│   ├── file-crypto.html    # Mã hóa / giải mã file & ảnh
│   ├── visualizer.html     # Trực quan hóa từng bước AES
│   ├── tests.html          # Chạy test suite
│   ├── source.html         # Xem mã nguồn có syntax highlight
│   └── about.html          # Nhóm thực hiện & tài liệu tham khảo
└── assets/
    └── icons/              # (Dự phòng)
```

---

## 🚀 Cách chạy

Mở file `index.html` bằng trình duyệt web — **không cần server** hay cài đặt gì thêm.

```bash
# Hoặc dùng local server:
python3 -m http.server 8080
# Sau đó mở http://localhost:8080
```

---

## ⚙️ Những gì được tự cài đặt

### `js/aes-core.js`

| Thành phần                   | Mô tả                                           |
| ---------------------------- | ----------------------------------------------- |
| `gmul(a, b)`                 | Nhân trong GF(2⁸) với đa thức bất khả quy 0x11B |
| `keyExpansion(key)`          | Mở rộng khóa — hỗ trợ AES-128/192/256           |
| `subBytes / invSubBytes`     | Thay thế byte qua S-Box / Inverse S-Box         |
| `shiftRows / invShiftRows`   | Dịch vòng hàng                                  |
| `mixColumns / invMixColumns` | Trộn cột trong GF(2⁸)                           |
| `addRoundKey`                | XOR state với round key                         |
| `aesEncryptBlock`            | Mã hóa 1 block 16 bytes                         |
| `aesDecryptBlock`            | Giải mã 1 block 16 bytes                        |
| `aesCBCEncrypt`              | Mã hóa CBC mode                                 |
| `aesCBCDecrypt`              | Giải mã CBC mode                                |

### `js/utils.js`

| Hàm                       | Mô tả                                       |
| ------------------------- | ------------------------------------------- |
| `strToBytes / bytesToStr` | UTF-8 encode/decode (hỗ trợ tiếng Việt)     |
| `toBase64 / fromBase64`   | Base64 encode/decode (không dùng btoa/atob) |
| `toHex / fromHex`         | Hex encode/decode                           |
| `randomBytes(n)`          | Sinh n bytes ngẫu nhiên (xorshift)          |
| `pkcs7Pad / pkcs7Unpad`   | PKCS#7 padding                              |

---

## ✅ Test Vectors

| Vector                | Nguồn               | Trạng thái |
| --------------------- | ------------------- | ---------- |
| AES-128 single block  | NIST FIPS 197 App.B | ✅         |
| AES-256 single block  | NIST FIPS 197 App.C | ✅         |
| AES-128-CBC           | RFC 3602 Case 1     | ✅         |
| Round-trip ASCII      | Internal            | ✅         |
| Round-trip tiếng Việt | Internal            | ✅         |
| Avalanche effect      | Internal            | ✅         |

---

## 📚 Tiêu chuẩn

- **NIST FIPS 197** — Advanced Encryption Standard (2001)
- **NIST SP 800-38A** — Recommendation for Block Cipher Modes (ECB, CBC, CFB, OFB, CTR)
- **RFC 3602** — AES-CBC Cipher Algorithm
- **Modes:** ECB, CBC, CFB, OFB, CTR
- **Padding:** PKCS#7 (ECB, CBC)

---

_Học viện Kỹ thuật Mật mã — Môn Cơ sở an toàn và bảo mật thông tin — 2025_

---

## 🆕 Mã hóa / Giải mã File & Hình ảnh

Trang `pages/file-crypto.html` bổ sung khả năng:

- **Mã hóa bất kỳ loại file**: PNG, JPG, GIF, PDF, TXT, ZIP, MP3, v.v.
- **Định dạng container `.aes`**: IV + tên file gốc + MIME type được nhúng tự động
- **Giải mã khôi phục file gốc**: tên file, MIME type được phục hồi chính xác
- **Xem trước hình ảnh**: so sánh ảnh gốc vs noise sau mã hóa
- **Entropy histogram**: phân tích phân phối byte trước/sau mã hóa
- **Preview nội dung text** sau khi giải mã
- **Lịch sử thao tác**: tải lại kết quả từ các lần trước
- **100% client-side**: không upload file lên server

### Định dạng file .aes (AESF Container)

```
[4 bytes]  Magic: "AESF"
[1 byte]   Key size marker (keyBits / 64)
[16 bytes] IV (Initialization Vector)
[4 bytes]  Filename length
[N bytes]  Original filename (UTF-8)
[4 bytes]  MIME type length
[M bytes]  MIME type (UTF-8)
[rest]     AES-CBC Ciphertext + PKCS#7 padding
```
