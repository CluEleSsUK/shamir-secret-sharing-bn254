import {aggregateGroupSignature, createPrivateKey, createPublicKey, sign, signPartial, split, verify} from "../src"

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

    it("single partial does not verify", () => {
        const m = Buffer.from("hello world")
        const sk = createPrivateKey()
        const pk = createPublicKey(sk)

        const partialKeys = split(sk, 3, 2)
        const partialSigs = partialKeys.map(k => ({ index: k.index, signature: signPartial(k, m) }))
        const finalSig = aggregateGroupSignature(partialSigs.slice(0, 1))

        expect(verify(pk, m, finalSig)).toBeFalsy()
    })
})