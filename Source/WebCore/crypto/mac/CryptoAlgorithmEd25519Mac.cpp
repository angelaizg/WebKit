//
//  CryptoAlgorithmEd25519.cpp
//  WebCore
//
//  Created by Ángela Izquierdo García on 14/9/22.
//

#include <stdio.h>
 /* CryptoAlgorithmEd25519 */
#include "config.h"
#include "CryptoAlgorithmEd25519.h"

#if ENABLE(WEB_CRYPTO)
#include "CommonCryptoUtilities.h"
#include "CryptoKeyEC.h"
#include <pal/spi/cocoa/CoreCryptoSPI.h>

namespace WebCore {
static ExceptionOr<Vector<uint8_t>> signEd25519(CryptoAlgorithmIdentifier hash, const PlatformECKey key, size_t keyLengthInBytes, const Vector<uint8_t>& data)
{
    
    /*
    CCDigestAlgorithm digestAlgorithm;
    if (!getCommonCryptoDigestAlgorithm(hash, digestAlgorithm))
        return Exception { OperationError };

    auto cryptoDigestAlgorithm = WebCore::cryptoDigestAlgorithm(hash);
    if (!cryptoDigestAlgorithm)
        return Exception { OperationError };
    auto digest = PAL::CryptoDigest::create(*cryptoDigestAlgorithm);
    if (!digest)
        return Exception { OperationError };
    digest->addBytes(data.data(), data.size());
    
    */
    /*
    auto digestData = digest->computeHash();

    // The signature produced by CCECCryptorSignHash is in DER format.
    // tag + length(1) + tag + length(1) + InitialOctet(?) + keyLength in bytes + tag + length(1) + InitialOctet(?) + keyLength in bytes
    Vector<uint8_t> signature(8 + keyLengthInBytes * 2);
    size_t signatureSize = signature.size();
    CCECCryptorRef ccecc_key = std::get<CCECCryptorRef>(key);
    CCCryptorStatus status = CCECCryptorSignHash(ccecc_key, digestData.data(), digestData.size(), signature.data(), &signatureSize);
    if (status)
        return Exception { OperationError };

    // FIXME: <rdar://problem/31618371>
    // convert the DER binary into r + s
    Vector<uint8_t> newSignature;
    newSignature.reserveInitialCapacity(keyLengthInBytes * 2);
    size_t offset = 1; // skip tag
    offset += bytesUsedToEncodedLength(signature[offset]); // skip length
    ++offset; // skip tag

    // If r < keyLengthInBytes, fill the head of r with 0s.
    size_t bytesToCopy = keyLengthInBytes;
    if (signature[offset] < keyLengthInBytes) {
        newSignature.grow(keyLengthInBytes - signature[offset]);
        memset(newSignature.data(), InitialOctet, keyLengthInBytes - signature[offset]);
        bytesToCopy = signature[offset];
    } else if (signature[offset] > keyLengthInBytes) // Otherwise skip the leading 0s of r.
        offset += signature[offset] - keyLengthInBytes;
    offset++; // skip length
    ASSERT_WITH_SECURITY_IMPLICATION(signature.size() > offset + bytesToCopy);
    newSignature.append(signature.data() + offset, bytesToCopy);
    offset += bytesToCopy + 1; // skip r, tag

    // If s < keyLengthInBytes, fill the head of s with 0s.
    bytesToCopy = keyLengthInBytes;
    if (signature[offset] < keyLengthInBytes) {
        size_t pos = newSignature.size();
        newSignature.resize(pos + keyLengthInBytes - signature[offset]);
        memset(newSignature.data() + pos, InitialOctet, keyLengthInBytes - signature[offset]);
        bytesToCopy = signature[offset];
    } else if (signature[offset] > keyLengthInBytes) // Otherwise skip the leading 0s of s.
        offset += signature[offset] - keyLengthInBytes;
    ++offset; // skip length
    ASSERT_WITH_SECURITY_IMPLICATION(signature.size() >= offset + bytesToCopy);
    newSignature.append(signature.data() + offset, bytesToCopy);

    return WTFMove(newSignature);
     */
    //Vector<uint8_t>& data
    const struct ccdigest_info *di = ccsha256_di();
    ccec25519signature signature ;
    cec25519pubkey pk;
    ccec25519secretkey sk
    cced25519_sign(di,
                        signature,
                        data.size(),
                        data,
                        pk,
                        sk);
    return WTFMove(signature);
    
}


ExceptionOr<Vector<uint8_t>> CryptoAlgorithmEd25519::platformSign(const CryptoAlgorithmEd25519Params& parameters, const CryptoKeyEC& key, const Vector<uint8_t>& data)
{
    return signEd25519(parameters.hashIdentifier, key.platformKey(), key.keySizeInBytes(), data);
}
}
