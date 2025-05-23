// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';
const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const crypto = require('crypto');
const fixtures = require('../common/fixtures');

crypto.DEFAULT_ENCODING = 'buffer';

//
// Test authenticated encryption modes.
//
// !NEVER USE STATIC IVs IN REAL LIFE!
//

const TEST_CASES = require(fixtures.path('aead-vectors.js'));

const errMessages = {
  auth: / auth/,
  state: / state/,
  FIPS: /not supported in FIPS mode/,
  length: /Invalid IV length/,
  authTagLength: /Invalid authentication tag length/
};

const ciphers = crypto.getCiphers();

const expectedWarnings = common.hasFipsCrypto ?
  [] : [
    ['Use Cipheriv for counter mode of aes-192-gcm'],
    ['Use Cipheriv for counter mode of aes-192-ccm'],
    ['Use Cipheriv for counter mode of aes-192-ccm'],
    ['Use Cipheriv for counter mode of aes-128-ccm'],
    ['Use Cipheriv for counter mode of aes-128-ccm'],
    ['Use Cipheriv for counter mode of aes-128-ccm'],
    ['Use Cipheriv for counter mode of aes-256-ccm'],
    ['Use Cipheriv for counter mode of aes-256-ccm'],
    ['Use Cipheriv for counter mode of aes-256-ccm'],
    ['Use Cipheriv for counter mode of aes-256-ccm'],
    ['Use Cipheriv for counter mode of aes-256-ccm'],
    ['Use Cipheriv for counter mode of aes-256-ccm'],
    ['Use Cipheriv for counter mode of aes-256-ccm'],
    ['Use Cipheriv for counter mode of aes-256-ccm'],
    ['Use Cipheriv for counter mode of aes-256-ccm'],
    ['Use Cipheriv for counter mode of aes-256-ccm'],
    ['Use Cipheriv for counter mode of aes-256-ccm'],
    ['Use Cipheriv for counter mode of aes-256-ccm'],
    ['Use Cipheriv for counter mode of aes-256-ccm']
  ];

const expectedDeprecationWarnings = [
  ['crypto.DEFAULT_ENCODING is deprecated.', 'DEP0091'],
  ['crypto.createCipher is deprecated.', 'DEP0106']
];

common.expectWarning({
  Warning: expectedWarnings,
  DeprecationWarning: expectedDeprecationWarnings
});

for (const test of TEST_CASES) {
  if (!ciphers.includes(test.algo)) {
    common.printSkipMessage(`unsupported ${test.algo} test`);
    continue;
  }

  if (common.hasFipsCrypto && test.iv.length < 24) {
    common.printSkipMessage('IV len < 12 bytes unsupported in FIPS mode');
    continue;
  }

  const isCCM = /^aes-(128|192|256)-ccm$/.test(test.algo);
  const isOCB = /^aes-(128|192|256)-ocb$/.test(test.algo);
  const isChacha20Poly1305 = test.algo === 'chacha20-poly1305';

  let options;
  if (isCCM || isOCB || isChacha20Poly1305)
    options = { authTagLength: test.tag.length / 2 };

  const inputEncoding = test.plainIsHex ? 'hex' : 'ascii';

  let aadOptions;
  if (isCCM) {
    aadOptions = {
      plaintextLength: Buffer.from(test.plain, inputEncoding).length
    };
  }

  {
    const encrypt = crypto.createCipheriv(test.algo,
                                          Buffer.from(test.key, 'hex'),
                                          Buffer.from(test.iv, 'hex'),
                                          options);

    if (test.aad)
      encrypt.setAAD(Buffer.from(test.aad, 'hex'), aadOptions);

    let hex = encrypt.update(test.plain, inputEncoding, 'hex');
    hex += encrypt.final('hex');

    const auth_tag = encrypt.getAuthTag();
    // Only test basic encryption run if output is marked as tampered.
    if (!test.tampered) {
      assert.strictEqual(hex, test.ct);
      assert.strictEqual(auth_tag.toString('hex'), test.tag);
    }
  }

  {
    if (isCCM && common.hasFipsCrypto) {
      assert.throws(() => {
        crypto.createDecipheriv(test.algo,
                                Buffer.from(test.key, 'hex'),
                                Buffer.from(test.iv, 'hex'),
                                options);
      }, errMessages.FIPS);
    } else {
      const decrypt = crypto.createDecipheriv(test.algo,
                                              Buffer.from(test.key, 'hex'),
                                              Buffer.from(test.iv, 'hex'),
                                              options);
      decrypt.setAuthTag(Buffer.from(test.tag, 'hex'));
      if (test.aad)
        decrypt.setAAD(Buffer.from(test.aad, 'hex'), aadOptions);

      const outputEncoding = test.plainIsHex ? 'hex' : 'ascii';

      let msg = decrypt.update(test.ct, 'hex', outputEncoding);
      if (!test.tampered) {
        msg += decrypt.final(outputEncoding);
        assert.strictEqual(msg, test.plain);
      } else {
        // Assert that final throws if input data could not be verified!
        assert.throws(function() { decrypt.final('hex'); }, errMessages.auth);
      }
    }
  }

  if (test.password) {
    if (common.hasFipsCrypto) {
      assert.throws(() => { crypto.createCipher(test.algo, test.password); },
                    errMessages.FIPS);
    } else {
      const encrypt = crypto.createCipher(test.algo, test.password, options);
      if (test.aad)
        encrypt.setAAD(Buffer.from(test.aad, 'hex'), aadOptions);
      let hex = encrypt.update(test.plain, 'ascii', 'hex');
      hex += encrypt.final('hex');
      const auth_tag = encrypt.getAuthTag();
      // Only test basic encryption run if output is marked as tampered.
      if (!test.tampered) {
        assert.strictEqual(hex, test.ct);
        assert.strictEqual(auth_tag.toString('hex'), test.tag);
      }
    }
  }

  if (test.password) {
    if (common.hasFipsCrypto) {
      assert.throws(() => { crypto.createDecipher(test.algo, test.password); },
                    errMessages.FIPS);
    } else {
      const decrypt = crypto.createDecipher(test.algo, test.password, options);
      decrypt.setAuthTag(Buffer.from(test.tag, 'hex'));
      if (test.aad)
        decrypt.setAAD(Buffer.from(test.aad, 'hex'), aadOptions);
      let msg = decrypt.update(test.ct, 'hex', 'ascii');
      if (!test.tampered) {
        msg += decrypt.final('ascii');
        assert.strictEqual(msg, test.plain);
      } else {
        // Assert that final throws if input data could not be verified!
        assert.throws(function() { decrypt.final('ascii'); }, errMessages.auth);
      }
    }
  }

  {
    // Trying to get tag before inputting all data:
    const encrypt = crypto.createCipheriv(test.algo,
                                          Buffer.from(test.key, 'hex'),
                                          Buffer.from(test.iv, 'hex'),
                                          options);
    encrypt.update('blah', 'ascii');
    assert.throws(function() { encrypt.getAuthTag(); }, errMessages.state);
  }

  {
    // Trying to create cipher with incorrect IV length
    assert.throws(function() {
      crypto.createCipheriv(
        test.algo,
        Buffer.from(test.key, 'hex'),
        Buffer.alloc(0)
      );
    }, errMessages.length);
  }
}

// Non-authenticating mode:
{
  const encrypt =
      crypto.createCipheriv('aes-128-cbc',
                            'ipxp9a6i1Mb4USb4',
                            '6fKjEjR3Vl30EUYC');
  encrypt.update('blah', 'ascii');
  encrypt.final();
  assert.throws(() => encrypt.getAuthTag(), errMessages.state);
  assert.throws(() => encrypt.setAAD(Buffer.from('123', 'ascii')),
                errMessages.state);
}

// GCM only supports specific authentication tag lengths, invalid lengths should
// throw.
{
  for (const length of [0, 1, 2, 6, 9, 10, 11, 17]) {
    common.expectsError(() => {
      const decrypt = crypto.createDecipheriv('aes-128-gcm',
                                              'FxLKsqdmv0E9xrQh',
                                              'qkuZpJWCewa6Szih');
      decrypt.setAuthTag(Buffer.from('1'.repeat(length)));
    }, {
      type: Error,
      message: `Invalid authentication tag length: ${length}`
    });

    common.expectsError(() => {
      crypto.createCipheriv('aes-256-gcm',
                            'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8',
                            'qkuZpJWCewa6Szih',
                            {
                              authTagLength: length
                            });
    }, {
      type: Error,
      message: `Invalid authentication tag length: ${length}`
    });

    common.expectsError(() => {
      crypto.createDecipheriv('aes-256-gcm',
                              'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8',
                              'qkuZpJWCewa6Szih',
                              {
                                authTagLength: length
                              });
    }, {
      type: Error,
      message: `Invalid authentication tag length: ${length}`
    });
  }
}

// Test that GCM can produce shorter authentication tags than 16 bytes.
{
  const fullTag = '1debb47b2c91ba2cea16fad021703070';
  for (const [authTagLength, e] of [[undefined, 16], [12, 12], [4, 4]]) {
    const cipher = crypto.createCipheriv('aes-256-gcm',
                                         'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8',
                                         'qkuZpJWCewa6Szih', {
                                           authTagLength
                                         });
    cipher.setAAD(Buffer.from('abcd'));
    cipher.update('01234567', 'hex');
    cipher.final();
    const tag = cipher.getAuthTag();
    assert.strictEqual(tag.toString('hex'), fullTag.substr(0, 2 * e));
  }
}

// Test that users can manually restrict the GCM tag length to a single value.
{
  const decipher = crypto.createDecipheriv('aes-256-gcm',
                                           'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8',
                                           'qkuZpJWCewa6Szih', {
                                             authTagLength: 8
                                           });

  common.expectsError(() => {
    // This tag would normally be allowed.
    decipher.setAuthTag(Buffer.from('1'.repeat(12)));
  }, {
    type: Error,
    message: 'Invalid authentication tag length: 12'
  });

  // The Decipher object should be left intact.
  decipher.setAuthTag(Buffer.from('445352d3ff85cf94', 'hex'));
  const text = Buffer.concat([
    decipher.update('3a2a3647', 'hex'),
    decipher.final()
  ]);
  assert.strictEqual(text.toString('utf8'), 'node');
}

// Test that create(De|C)ipher(iv)? throws if the mode is CCM and an invalid
// authentication tag length has been specified.
{
  for (const authTagLength of [-1, true, false, NaN, 5.5]) {
    common.expectsError(() => {
      crypto.createCipheriv('aes-256-ccm',
                            'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8',
                            'qkuZpJWCewa6S',
                            {
                              authTagLength
                            });
    }, {
      type: TypeError,
      code: 'ERR_INVALID_OPT_VALUE',
      message: `The value "${authTagLength}" is invalid for option ` +
               '"authTagLength"'
    });

    common.expectsError(() => {
      crypto.createDecipheriv('aes-256-ccm',
                              'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8',
                              'qkuZpJWCewa6S',
                              {
                                authTagLength
                              });
    }, {
      type: TypeError,
      code: 'ERR_INVALID_OPT_VALUE',
      message: `The value "${authTagLength}" is invalid for option ` +
               '"authTagLength"'
    });

    if (!common.hasFipsCrypto) {
      common.expectsError(() => {
        crypto.createCipher('aes-256-ccm', 'bad password', { authTagLength });
      }, {
        type: TypeError,
        code: 'ERR_INVALID_OPT_VALUE',
        message: `The value "${authTagLength}" is invalid for option ` +
                 '"authTagLength"'
      });

      common.expectsError(() => {
        crypto.createDecipher('aes-256-ccm', 'bad password', { authTagLength });
      }, {
        type: TypeError,
        code: 'ERR_INVALID_OPT_VALUE',
        message: `The value "${authTagLength}" is invalid for option ` +
                 '"authTagLength"'
      });
    }
  }

  // The following values will not be caught by the JS layer and thus will not
  // use the default error codes.
  for (const authTagLength of [0, 1, 2, 3, 5, 7, 9, 11, 13, 15, 17, 18]) {
    assert.throws(() => {
      crypto.createCipheriv('aes-256-ccm',
                            'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8',
                            'qkuZpJWCewa6S',
                            {
                              authTagLength
                            });
    }, errMessages.authTagLength);

    if (!common.hasFipsCrypto) {
      assert.throws(() => {
        crypto.createDecipheriv('aes-256-ccm',
                                'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8',
                                'qkuZpJWCewa6S',
                                {
                                  authTagLength
                                });
      }, errMessages.authTagLength);

      assert.throws(() => {
        crypto.createCipher('aes-256-ccm', 'bad password', { authTagLength });
      }, errMessages.authTagLength);

      assert.throws(() => {
        crypto.createDecipher('aes-256-ccm', 'bad password', { authTagLength });
      }, errMessages.authTagLength);
    }
  }
}

// Test that create(De|C)ipher(iv)? throws if the mode is CCM or OCB and no
// authentication tag has been specified.
{
  for (const mode of ['ccm']) {
    assert.throws(() => {
      crypto.createCipheriv(`aes-256-${mode}`,
                            'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8',
                            'qkuZpJWCewa6S');
    }, {
      message: `authTagLength required for aes-256-${mode}`
    });

    // CCM decryption and create(De|C)ipher are unsupported in FIPS mode.
    if (!common.hasFipsCrypto) {
      assert.throws(() => {
        crypto.createDecipheriv(`aes-256-${mode}`,
                                'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8',
                                'qkuZpJWCewa6S');
      }, {
        message: `authTagLength required for aes-256-${mode}`
      });

      assert.throws(() => {
        crypto.createCipher(`aes-256-${mode}`, 'very bad password');
      }, {
        message: `authTagLength required for aes-256-${mode}`
      });

      assert.throws(() => {
        crypto.createDecipher(`aes-256-${mode}`, 'very bad password');
      }, {
        message: `authTagLength required for aes-256-${mode}`
      });
    }
  }
}

// Test that setAAD throws if an invalid plaintext length has been specified.
{
  const cipher = crypto.createCipheriv('aes-256-ccm',
                                       'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8',
                                       'qkuZpJWCewa6S',
                                       {
                                         authTagLength: 10
                                       });

  for (const plaintextLength of [-1, true, false, NaN, 5.5]) {
    common.expectsError(() => {
      cipher.setAAD(Buffer.from('0123456789', 'hex'), { plaintextLength });
    }, {
      type: TypeError,
      code: 'ERR_INVALID_OPT_VALUE',
      message: `The value "${plaintextLength}" is invalid for option ` +
               '"plaintextLength"'
    });
  }
}

// Test that setAAD and update throw if the plaintext is too long.
{
  for (const ivLength of [13, 12]) {
    const maxMessageSize = (1 << (8 * (15 - ivLength))) - 1;
    const key = 'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8';
    const cipher = () => crypto.createCipheriv('aes-256-ccm', key,
                                               '0'.repeat(ivLength),
                                               {
                                                 authTagLength: 10
                                               });

    assert.throws(() => {
      cipher().setAAD(Buffer.alloc(0), {
        plaintextLength: maxMessageSize + 1
      });
    }, /^Error: Message exceeds maximum size$/);

    const msg = Buffer.alloc(maxMessageSize + 1);
    assert.throws(() => {
      cipher().update(msg);
    }, /^Error: Message exceeds maximum size$/);

    const c = cipher();
    c.setAAD(Buffer.alloc(0), {
      plaintextLength: maxMessageSize
    });
    c.update(msg.slice(1));
  }
}

// Test that setAAD throws if the mode is CCM and the plaintext length has not
// been specified.
{
  assert.throws(() => {
    const cipher = crypto.createCipheriv('aes-256-ccm',
                                         'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8',
                                         'qkuZpJWCewa6S',
                                         {
                                           authTagLength: 10
                                         });
    cipher.setAAD(Buffer.from('0123456789', 'hex'));
  }, /^Error: plaintextLength required for CCM mode with AAD$/);

  if (!common.hasFipsCrypto) {
    assert.throws(() => {
      const cipher = crypto.createDecipheriv('aes-256-ccm',
                                             'FxLKsqdmv0E9xrQhp0b1ZgI0K7JFZJM8',
                                             'qkuZpJWCewa6S',
                                             {
                                               authTagLength: 10
                                             });
      cipher.setAAD(Buffer.from('0123456789', 'hex'));
    }, /^Error: plaintextLength required for CCM mode with AAD$/);
  }
}

// Test that final() throws in CCM mode when no authentication tag is provided.
{
  if (!common.hasFipsCrypto) {
    const key = Buffer.from('1ed2233fa2223ef5d7df08546049406c', 'hex');
    const iv = Buffer.from('7305220bca40d4c90e1791e9', 'hex');
    const ct = Buffer.from('8beba09d4d4d861f957d51c0794f4abf8030848e', 'hex');
    const decrypt = crypto.createDecipheriv('aes-128-ccm', key, iv, {
      authTagLength: 10
    });
    // Normally, we would do this:
    // decrypt.setAuthTag(Buffer.from('0d9bcd142a94caf3d1dd', 'hex'));
    assert.throws(() => {
      decrypt.setAAD(Buffer.from('63616c76696e', 'hex'), {
        plaintextLength: ct.length
      });
      decrypt.update(ct);
      decrypt.final();
    }, errMessages.state);
  }
}

// Test that setAuthTag does not throw in GCM mode when called after setAAD.
{
  const key = Buffer.from('1ed2233fa2223ef5d7df08546049406c', 'hex');
  const iv = Buffer.from('579d9dfde9cd93d743da1ceaeebb86e4', 'hex');
  const decrypt = crypto.createDecipheriv('aes-128-gcm', key, iv);
  decrypt.setAAD(Buffer.from('0123456789', 'hex'));
  decrypt.setAuthTag(Buffer.from('1bb9253e250b8069cde97151d7ef32d9', 'hex'));
  assert.strictEqual(decrypt.update('807022', 'hex', 'hex'), 'abcdef');
  assert.strictEqual(decrypt.final('hex'), '');
}

// Test that an IV length of 11 does not overflow max_message_size_.
{
  const key = 'x'.repeat(16);
  const iv = Buffer.from('112233445566778899aabb', 'hex');
  const options = { authTagLength: 8 };
  const encrypt = crypto.createCipheriv('aes-128-ccm', key, iv, options);
  encrypt.update('boom');  // Should not throw 'Message exceeds maximum size'.
  encrypt.final();
}

// Test that the authentication tag can be set at any point before calling
// final() in GCM or OCB mode.
{
  const plain = Buffer.from('Hello world', 'utf8');
  const key = Buffer.from('0123456789abcdef', 'utf8');
  const iv = Buffer.from('0123456789ab', 'utf8');

  for (const mode of ['gcm']) {
    for (const authTagLength of mode === 'gcm' ? [undefined, 8] : [8]) {
      const cipher = crypto.createCipheriv(`aes-128-${mode}`, key, iv, {
        authTagLength
      });
      const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
      const authTag = cipher.getAuthTag();

      for (const authTagBeforeUpdate of [true, false]) {
        const decipher = crypto.createDecipheriv(`aes-128-${mode}`, key, iv, {
          authTagLength
        });
        if (authTagBeforeUpdate) {
          decipher.setAuthTag(authTag);
        }
        const resultUpdate = decipher.update(ciphertext);
        if (!authTagBeforeUpdate) {
          decipher.setAuthTag(authTag);
        }
        const resultFinal = decipher.final();
        const result = Buffer.concat([resultUpdate, resultFinal]);
        assert(result.equals(plain));
      }
    }
  }
}

// Test that setAuthTag can only be called once.
{
  const plain = Buffer.from('Hello world', 'utf8');
  const key = Buffer.from('0123456789abcdef', 'utf8');
  const iv = Buffer.from('0123456789ab', 'utf8');
  const opts = { authTagLength: 8 };

  for (const mode of ['gcm', 'ccm']) {
    const cipher = crypto.createCipheriv(`aes-128-${mode}`, key, iv, opts);
    const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
    const tag = cipher.getAuthTag();

    const decipher = crypto.createDecipheriv(`aes-128-${mode}`, key, iv, opts);
    decipher.setAuthTag(tag);
    assert.throws(() => {
      decipher.setAuthTag(tag);
    }, errMessages.state);
    // Decryption should still work.
    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);
    assert(plain.equals(plaintext));
  }
}
