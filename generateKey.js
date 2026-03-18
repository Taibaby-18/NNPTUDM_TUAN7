const crypto = require('crypto');
const fs = require('fs');

// Tạo cặp khóa RSA 2048 bits
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Lưu ra 2 file
fs.writeFileSync('public.pem', publicKey);
fs.writeFileSync('private.pem', privateKey);

console.log(">>> Đã tạo thành công public.pem và private.pem!");