const base32 = require('hi-base32');
const crypto = require('crypto');
const QRCode = require('qrcode');

function generateSecret(length = 20) {
  const buffer = crypto.randomBytes(length);
  return base32.encode(buffer).replace(/=+$/, ''); // Remove padding
}

function generateTOTP(secret, timeStep = 30, digits = 6, algorithm = 'sha1') {
  const decodedSecret = base32.decode.asBytes(secret);
  const time = Math.floor(Date.now() / 1000);
  const counter = Math.floor(time / timeStep);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeUInt32BE(counter, 4);

  const hmac = crypto.createHmac(algorithm, Buffer.from(decodedSecret));
  hmac.update(counterBuffer);
  const hash = hmac.digest();

  const offset = hash[hash.length - 1] & 0xf;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const otp = binary % 10 ** digits;
  return otp.toString().padStart(digits, '0');
}

function generateQRCodeString(
    secret,
    accountName = 'user@example.com',
    issuer = 'MyApp',
    timeStep = 30,
    digits = 6,
    algorithm = 'sha1'
) {
  const otpAuthUrl = `otpauth://totp/${issuer}:${accountName}?secret=${secret}&issuer=${issuer}&algorithm=${algorithm}&digits=${digits}&period=${timeStep}`;

  return otpAuthUrl;
}

function generateQRCode(
    secret,
    accountName = 'user@example.com',
    issuer = 'MyApp',
    timeStep = 30,
    digits = 6,
    algorithm = 'sha1'
) {
  const otpAuthUrl = generateQRCodeString(
    secret,
    accountName,
    issuer,
    timeStep,
    digits,
    algorithm
  );

  // Print QR code to console
  QRCode.toString(otpAuthUrl, { type: 'terminal' }, (err, url) => {
    if (err) throw err;
    console.log(url);
  });
}

// Auto-refresh and print TOTP token
function autoRefreshTOTP(secret, timeStep = 30, digits = 6, algorithm = 'sha1') {
  function refreshToken() {
    const token = generateTOTP(secret, timeStep, digits, algorithm);
    console.log('New TOTP Token:', token);

    // Calculate the remaining time until the next refresh
    const timeRemaining = timeStep - (Math.floor(Date.now() / 1000) % timeStep);
    setTimeout(refreshToken, timeRemaining * 1000);
  }

  // Start the refresh loop
  refreshToken();
}

// const secret = generateSecret();
const secret = "JBSWY3DPEHPK3PXP";
const accountName = 'user@example.com';
const issuer = 'MyApp';
const timeStep = 30;
const digits = 6;
const algorithm = 'sha1';

console.log("TOTP Authenticator Parameter:");
console.log(`\tSecret         : ${secret}`);
console.log(`\tAccount Name   : ${accountName}`);
console.log(`\tIssuer         : ${issuer}`);
console.log(`\tTime Step      : ${timeStep}`);
console.log(`\tDigits         : ${digits}`);
console.log(`\tAlgorithm      : ${algorithm}`);
console.log(`\r\n`);

generateQRCode(secret, accountName, issuer, timeStep, digits, algorithm);
autoRefreshTOTP(secret, timeStep, digits, algorithm);