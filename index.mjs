import crypto from 'crypto';
import base32Encode from 'base32-encode';
import base32Decode from 'base32-decode';
import util from 'util';

// Generating mfa secret block of code

//*************************************************************//
const generateMfaSecret = async () => {
     const buffer = await util.promisify(crypto.randomBytes)(16);
    const mfaSecret = base32Encode(buffer, 'RFC4648', { padding: false });
    console.log(mfaSecret)
    return mfaSecret;
  };



  const mfaSecret = await generateMfaSecret();
  //*************************************************************//




  // Generate temporary TOTP

  //*************************************************************//


  const generateHOTP = (secret, counter) => {
    const decodedSecret = base32Decode(secret, 'RFC4648');
  
    const buffer = Buffer.alloc(8);
    for (let i = 0; i < 8; i++) {
      buffer[7 - i] = counter & 0xff;
      counter = counter >> 8;
    }

    // Step 1: Generate an HMAC-SHA-1 value
  const hmac = crypto.createHmac('sha1', Buffer.from(decodedSecret));
  hmac.update(buffer);
  const hmacResult = hmac.digest();

  // Step 2: Generate a 4-byte string (Dynamic Truncation)
  const offset = hmacResult[hmacResult.length - 1] & 0xf;
  const code =
    ((hmacResult[offset] & 0x7f) << 24) |
    ((hmacResult[offset + 1] & 0xff) << 16) |
    ((hmacResult[offset + 2] & 0xff) << 8) |
    (hmacResult[offset + 3] & 0xff);

 console.log('HOTP', `${code % 10 ** 6}`.padStart(6, '0'));

  // Step 3: Compute an HOTP 30sec
  return `${code % 10 ** 6}`.padStart(6, '0');
}

  const generateTOTP = (secret, window = 0) => {
    const counter = Math.floor(Date.now() / 30000);
    console.log('counter', counter)
    return generateHOTP(secret, counter + window);
  }

  const generatedTOTP = generateTOTP(null, 0);

   //*************************************************************//



   // Verify generated TOTP 
   //*************************************************************//

   const verifyTOTP = (token, secret, window = 1) => {
    for (let errorWindow = -window; errorWindow <= +window; errorWindow++) {
      const totp = generateTOTP(secret, errorWindow);
      if (token === totp) {
        return true;
      }
    }
    return false;
  }

   const result = verifyTOTP(generatedTOTP, mfaSecret)

  //*************************************************************//
