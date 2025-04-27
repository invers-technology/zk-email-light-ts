pragma circom 2.1.6;

include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/utils/array.circom";
include "@zk-email/circuits/utils/bytes.circom";

// Copy from https://github.com/zkemail/zk-email-verify/blob/main/packages/circuits/email-verifier.circom

template Dkim() {
    // RSA field operations constants
    // Sub field bits
    var N = 121;
    // Number of sub fields
    var K = 17;

    // Header length
    var L = 640;

    signal input emailHeader[L];
    signal input emailHeaderLength;
    signal input pubkey[K];
    signal input signature[K];

    // Assert `emailHeader` data after `emailHeaderLength` are zeros
    AssertZeroPadding(L)(emailHeader, emailHeaderLength);

    // Calculate SHA256 hash of the `emailHeader` - 506,670 constraints
    signal sha[256] <== Sha256Bytes(L)(emailHeader, emailHeaderLength);
    component bitPacker = PackBits(256, 128);
    bitPacker.in <== sha;
    signal output shaHi <== bitPacker.out[0];
    signal output shaLo <== bitPacker.out[1];

    // Pack SHA output bytes to int[] for RSA input message
    var rsaMessageSize = (256 + N) \ N;
    component rsaMessage[rsaMessageSize];
    for (var i = 0; i < rsaMessageSize; i++) {
        rsaMessage[i] = Bits2Num(N);
    }
    for (var i = 0; i < 256; i++) {
        rsaMessage[i \ N].in[i % N] <== sha[255 - i];
    }
    for (var i = 256; i < N * rsaMessageSize; i++) {
        rsaMessage[i \ N].in[i % N] <== 0;
    }

    // Verify RSA signature - 149,251 constraints
    component rsaVerifier = RSAVerifier65537(N, K);
    for (var i = 0; i < rsaMessageSize; i++) {
        rsaVerifier.message[i] <== rsaMessage[i].out;
    }
    for (var i = rsaMessageSize; i < K; i++) {
        rsaVerifier.message[i] <== 0;
    }
    rsaVerifier.modulus <== pubkey;
    rsaVerifier.signature <== signature;
}
