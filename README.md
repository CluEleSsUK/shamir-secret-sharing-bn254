# shamir-secret-sharing-bn254
![build](https://github.com/CluEleSsUK/shamir-secret-sharing-bn254/actions/workflows/build.yml/badge.svg)

A user-friendly wrapper around [@noble/curves](https://github.com/paulmillr/noble-curves) for creating a secret, splitting it into keyshares, and operating with the keyshares.
Public keys are on $G2$ and signatures are on $G1$.


## Usage
Install by running `npm install shamir-secret-sharing-bn254`

Use as follows:
```ts
import {createSecretKey, split, signPartial, aggregateSignature, verify} from "shamir-secret-sharing-bn254"

const secretKey = createSecretKey()
const publicKey = createPublicKey(secretKey)

// split the secret key into 3 parts, requiring 2 signers to reconstruct the signature
const shareCount = 3
const threshold = 2
const shares = split(secretKey, shareCount, threshold)

// now you'd give each of your key shares to some party,
// and they'd sign a message with their share as follows
const myShare = "" // imagine this is the share they received from `shares` above
const message = "hello world"
const messageAsBytes = new TextEncoder().encode(message)
const partialSignature = signPartial(myShare, messageAsBytes)

// once you've received `threshold` count of partial signatures, 
// you can reconstruct a valid group signature and verify it as follows
const partialSignatures = [] // imagine we've gathered this from our shareholders; we need `threshold` or more!
const groupSignature = aggregateGroupSignature(partialSignatures)
const success = verify(publicKey, message, groupSignature) 
assert(success) // this will blow up if your signature is invalid!

```
