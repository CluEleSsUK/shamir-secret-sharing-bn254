import {bn254} from "@kevincharm/noble-bn254-drand"
import {randomBytes} from "@noble/hashes/utils"

// these are some helper wrappers so you don't end up passing the wrong byte array to the wrong function.
// most functions take both variants anyway
export type SecretKey = { sk: Uint8Array }
export type PublicKey = { pk: Uint8Array }
export type PublicKeyShare = { index: bigint, pk: Uint8Array }
export type SecretKeyShare = { index: bigint, share: bigint }

export function createPrivateKey(): SecretKey {
    return {sk: bn254.utils.randomPrivateKey()}
}

export function createPublicKey(secretKey: SecretKey | Uint8Array): PublicKey {
    const sk = secretKey instanceof Uint8Array ? secretKey : secretKey.sk
    const fieldElement = bn254.fields.Fr.fromBytes(sk)
    const pk = bn254.G2.ProjectivePoint.BASE.multiply(fieldElement)
    return {pk: pk.toRawBytes()}
}

export function createPublicKeyShare(secretKeyShare: SecretKeyShare): PublicKeyShare {
    return {
        index: secretKeyShare.index,
        pk: bn254.G2.ProjectivePoint.BASE.multiply(secretKeyShare.share).toRawBytes()
    }
}

export function sign(secretKey: SecretKey | Uint8Array, message: Uint8Array): Uint8Array {
    const sk = secretKey instanceof Uint8Array ? secretKey : secretKey.sk
    return bn254.signShortSignature(message, sk)
}

export function signPartial(secretKeyShare: SecretKeyShare, message: Uint8Array): Uint8Array {
    const share = secretKeyShare instanceof Uint8Array ? secretKeyShare : secretKeyShare.share
    return bn254.signShortSignature(message, share)
}

export function verify(publicKey: PublicKey | Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    const pk = publicKey instanceof Uint8Array ? publicKey : publicKey.pk
    return bn254.verifyShortSignature(signature, message, pk)
}

export function verifyPartial(publicKey: PublicKeyShare | Uint8Array, message: Uint8Array, partialSignature: PartialSignature | Uint8Array): boolean {
    const sig = partialSignature instanceof Uint8Array ? partialSignature : partialSignature.signature
    const pk = publicKey instanceof Uint8Array ? publicKey : publicKey.pk
    return bn254.verifyShortSignature(sig, message, pk)
}

export type PartialSignature = { index: bigint, signature: Uint8Array }
const Fr = bn254.fields.Fr

// aggregatePartialSignatures takes an array of partial signatures and creates a final group signature
// (presuming there are threshold or more partials!)
export function aggregateGroupSignature(partials: Array<PartialSignature>): Uint8Array {
    const xs = partials.map((entry) => entry.index)
    let agg = bn254.G1.ProjectivePoint.ZERO

    for (let i = 0; i < partials.length; i++) {
        const entry = partials[i]
        const sig = bn254.G1.ProjectivePoint.fromHex(entry.signature)
        const term = sig.multiply(lagrangeCoeff0(i, xs))
        agg = agg.add(term)
    }

    return agg.toRawBytes()
}

function lagrangeCoeff0(index: number, xs: bigint[]): bigint {
    const xi = xs[index]
    if (!xi) {
        throw new Error("xi expected a value")
    }
    let num = 1n
    let den = 1n
    for (let i = 0; i < xs.length; i++) {
        if (i === index) continue
        const xj = xs[i]
        if (!xj) {
            throw new Error("xj expected a value")
        }
        num = Fr.mul(num, Fr.neg(xj))      // (0 − xj)
        den = Fr.mul(den, Fr.sub(xi, xj))  // (xi − xj)
    }
    return Fr.div(num, den)
}

// split splits a secret key into `n` shares with threshold `t`
export function split(secretKey: SecretKey | Uint8Array, numberOfShares: number, threshold: number): Array<SecretKeyShare> {
    const sk = secretKey instanceof Uint8Array ? secretKey : secretKey.sk
    if (threshold > numberOfShares) {
        throw new Error("threshold can'threshold be lower than node count - you probably have the parameters the wrong way round")
    }
    if (threshold < 2) {
        throw new Error("threshold less than two means everyone can recover the secret")
    }

    // sample random polynomial of degree (threshold-1), evaluations[0]=secret
    const evaluations: bigint[] = [encodeBigint(sk)]
    for (let i = 1; i < threshold; i++) {
        evaluations.push(randomFr())
    }

    // evaluate at x = 1..numberOfShares
    const shares: Array<SecretKeyShare> = []
    for (let x = 1n; x <= numberOfShares; x++) {
        let share = 0n
        // horner’s method: share = evaluations[0] + evaluations[1]*x + ... + evaluations[threshold-1]*x^(threshold-1)
        for (let i = evaluations.length - 1; i >= 0; i--) {
            const rhs = evaluations[i]
            if (!rhs) {
                throw new Error("invalid split")
            }
            share = bn254.fields.Fr.add(bn254.fields.Fr.mul(share, x), rhs)
        }
        shares.push({index: x, share})
    }

    return shares
}

function randomFr(): bigint {
    while (true) {
        const fr = encodeBigint(randomBytes(bn254.fields.Fr.BYTES))
        if (fr < bn254.fields.Fr.ORDER) {
            return fr
        }
    }
}

function encodeBigint(input: Uint8Array): bigint {
    return bn254.fields.Fr.fromBytes(input)
}
