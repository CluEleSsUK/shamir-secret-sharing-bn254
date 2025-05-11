type SecretKey = {
    sk: Uint8Array;
};
type PublicKey = {
    pk: Uint8Array;
};
type SecretKeyShare = {
    index: bigint;
    share: bigint;
};
export declare function createPrivateKey(): SecretKey;
export declare function createPublicKey(secretKey: SecretKey): PublicKey;
export declare function sign(sk: SecretKey, message: Uint8Array): Uint8Array;
export declare function signPartial(sk: SecretKeyShare, message: Uint8Array): Uint8Array;
export declare function verify(pk: PublicKey, message: Uint8Array, signature: Uint8Array): boolean;
type PartialSignature = {
    index: bigint;
    signature: Uint8Array;
};
export declare function aggregateSignatures(partials: Array<PartialSignature>): Uint8Array;
export declare function split(secret: SecretKey, t: number, n: number): Array<SecretKeyShare>;
export {};
