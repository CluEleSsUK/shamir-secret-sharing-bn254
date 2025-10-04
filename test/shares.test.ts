import {
    aggregateGroupSignature,
    createPrivateKey,
    createPublicKey,
    createPublicKeyShare,
    sign,
    signPartial,
    split,
    verify, verifyPartial
} from "../src"

describe("shares", () => {
    it("full private key can sign and verify", () => {
        const m = Buffer.from("hello world")
        const sk = createPrivateKey()
        const pk = createPublicKey(sk)
        const s = sign(sk, m)
        expect(verify(pk, m, s)).toBeTruthy()
    })

    it("reconstructed partials verify", () => {
        const m = Buffer.from("hello world")
        const sk = createPrivateKey()
        const pk = createPublicKey(sk)

        const partialKeys = split(sk, 3, 2)
        const partialSigs = partialKeys.map(k => ({ index: k.index, signature: signPartial(k, m) }))
        const finalSig = aggregateGroupSignature(partialSigs)

        expect(verify(pk, m, finalSig)).toBeTruthy()
    })

    it("threshold signatures verify", () => {
        const m = Buffer.from("hello world")
        const sk = createPrivateKey()
        const pk = createPublicKey(sk)

        const partialKeys = split(sk, 3, 2)
        const partialSigs = partialKeys.map(k => ({ index: k.index, signature: signPartial(k, m) }))
        const finalSig = aggregateGroupSignature(partialSigs.slice(0, 2))

        expect(verify(pk, m, finalSig)).toBeTruthy()
    })

    it("threshold signatures in funny order verify", () => {
        const m = Buffer.from("hello world")
        const sk = createPrivateKey()
        const pk = createPublicKey(sk)

        const partialKeys = split(sk, 3, 2)
        const partialSigs = partialKeys.map(k => ({ index: k.index, signature: signPartial(k, m) }))
        const finalSig = aggregateGroupSignature([partialSigs[1], partialSigs[0]])

        expect(verify(pk, m, finalSig)).toBeTruthy()
    })


    it("indexes matter for aggregation", () => {
        const m = Buffer.from("hello world")
        const sk = createPrivateKey()
        const pk = createPublicKey(sk)

        const partialKeys = split(sk, 3, 2)
        const partialSigs = partialKeys.map(k => ({ index: k.index, signature: signPartial(k, m) }))
        const finalSig = aggregateGroupSignature([{ index: 1n, signature: partialSigs[1].signature }, {
            index: 2n,
            signature: partialSigs[0].signature
        }])

        expect(verify(pk, m, finalSig)).toBeFalsy()
    })

    it("single partial does not verify for group public key", () => {
        const m = Buffer.from("hello world")
        const sk = createPrivateKey()
        const pk = createPublicKey(sk)

        const partialKeys = split(sk, 3, 2)
        const partialSigs = partialKeys.map(k => ({ index: k.index, signature: signPartial(k, m) }))
        const finalSig = aggregateGroupSignature(partialSigs.slice(0, 1))

        expect(verify(pk, m, finalSig)).toBeFalsy()
    })

    it("single partial verifies for its own public key", () => {
        const m = Buffer.from("hello world")
        const sk = createPrivateKey()

        const partialKeys = split(sk, 3, 2)
        const partialPublicKeys = partialKeys.map(it => createPublicKeyShare(it))
        const partialSigs = partialKeys.map(k => ({ index: k.index, signature: signPartial(k, m) }))

        for (let i = 0; i < partialKeys.length; i++) {
            expect(verifyPartial(partialPublicKeys[i], m, partialSigs[i])).toBeTruthy()
        }
    })

    it("single partial doesn't verify for other partial public keys", () => {
        const m = Buffer.from("hello world")
        const sk = createPrivateKey()

        const partialKeys = split(sk, 3, 2)
        const partialPublicKeys = partialKeys.map(it => createPublicKeyShare(it))
        const partialSigs = partialKeys.map(k => ({ index: k.index, signature: signPartial(k, m) }))

        // we check the partial sig against the wrong public key
        // ... you never know, strange mistakes happen :^)
        expect(verifyPartial(partialPublicKeys[0], m, partialSigs[1])).toBeFalsy()
    })

    it("passing arrays rather than magical objects to the verify partial function succeeds", () => {
        const m = Buffer.from("hello world")
        const sk = createPrivateKey()
        const pk = createPublicKey(sk)

        const sig1 = sign(sk, m)
        const sig2 = sign(sk.sk, m)
        expect(verify(pk, m, sig1)).toBeTruthy()
        expect(verify(pk.pk, m, sig1)).toBeTruthy()
        expect(verify(pk, m, sig2)).toBeTruthy()
        expect(verify(pk.pk, m, sig2)).toBeTruthy()

        const partialKeys = split(sk, 3, 2)
        const partialPublicKeys = partialKeys.map(it => createPublicKeyShare(it))
        const partialSigs = partialKeys.map(k => ({ index: k.index, signature: signPartial(k, m) }))

        expect(verifyPartial(partialPublicKeys[0].pk, m, partialSigs[0].signature)).toBeTruthy()
        expect(verifyPartial(partialPublicKeys[0].pk, m, partialSigs[0])).toBeTruthy()
        expect(verifyPartial(partialPublicKeys[0], m, partialSigs[0].signature)).toBeTruthy()
    })

    it("passing a custom DST works", () => {
        const DST = Buffer.from("wow-thats-funny")
        const m = Buffer.from("hello world")
        const sk = createPrivateKey()
        const pk = createPublicKey(sk)

        const partialKeys = split(sk, 3, 2)
        const partialSigs = partialKeys.map(k => ({ index: k.index, signature: signPartial(k, m, DST) }))
        const finalSig = aggregateGroupSignature(partialSigs)

        expect(verify(pk, m, finalSig, DST)).toBeTruthy()
    })

    it("mismatch in DST fails", () => {
        const DST = Buffer.from("wow-thats-funny")
        const m = Buffer.from("hello world")
        const sk = createPrivateKey()
        const pk = createPublicKey(sk)

        const partialKeys = split(sk, 3, 2)
        const partialSigs = partialKeys.map(k => ({ index: k.index, signature: signPartial(k, m, DST) }))
        const finalSig = aggregateGroupSignature(partialSigs)

        expect(verify(pk, m, finalSig, Buffer.from("wrong-dst"))).toBeFalsy()
    })
})
