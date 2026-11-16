'use strict'

var test = require('tape')
var nodeCrypto = require('../')
var myCrypto = require('../browser')

var zeros = '0000000000000000000000000000000000000000000000000000000000000000'

// (5, 0) has order 2 on y^2 = x^3 - 3x - 110, a curve sharing P-256's field and `a`, but is not on P-256
var offCurveP256 = '04' + zeros.slice(1) + '5' + zeros

// (1, 1) is not on secp256k1
var offCurveK1 = '04' + zeros.slice(1) + '1' + zeros.slice(1) + '1'

// (0, -1) is on edwards25519, but has order 2, so is outside the prime-order subgroup
var lowOrderEd25519 = '04' + zeros + '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec'

// (sqrt(-1), 0) is on edwards25519, but has order 4, so is outside the prime-order subgroup
var order4Ed25519 = '04' + '2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0' + zeros

// x = 1 is a low-order (order 4) Montgomery x-coordinate, outside the prime-order subgroup of curve25519
var lowOrderCurve25519 = zeros.slice(1) + '1'

function rejects (t, impl, curve, pub, privHex) {
  var dh = impl(curve)
  if (privHex) {
    dh.setPrivateKey(privHex, 'hex')
  } else {
    dh.generateKeys()
  }
  t['throws'](
    function () { dh.computeSecret(pub, 'hex') },
    curve + ': computeSecret rejects an invalid public key'
  )
}

test('invalid public keys', function (t) {
  ['01', '02', '03', '04'].forEach(function (k) {
    var priv = zeros.slice(k.length) + k
    rejects(t, myCrypto, 'prime256v1', offCurveP256, priv)
    rejects(t, nodeCrypto, 'prime256v1', offCurveP256, priv)
  })

  rejects(t, myCrypto, 'secp256k1', offCurveK1)
  rejects(t, nodeCrypto, 'secp256k1', offCurveK1)

  rejects(t, myCrypto, 'ed25519', lowOrderEd25519)
  rejects(t, myCrypto, 'ed25519', order4Ed25519)

  rejects(t, myCrypto, 'curve25519', zeros)
  rejects(t, myCrypto, 'curve25519', lowOrderCurve25519)

  t.test('error message matches node', function (st) {
    var dh = myCrypto('prime256v1')
    dh.generateKeys()
    st['throws'](
      function () { dh.computeSecret(offCurveP256, 'hex') },
      /^Error: Public key is not valid for specified curve$/
    )
    st.end()
  })

  t.test('setPublicKey', function (st) {
    var dh = myCrypto('prime256v1')
    dh.generateKeys()
    var pub = dh.getPublicKey('hex')
    st['throws'](
      function () { dh.setPublicKey(offCurveP256, 'hex') },
      /^Error: Public key is not valid for specified curve$/,
      'rejects an off-curve public key'
    )
    st.equal(dh.getPublicKey('hex'), pub, 'public key is unchanged')
    st.end()
  })

  t.end()
})
