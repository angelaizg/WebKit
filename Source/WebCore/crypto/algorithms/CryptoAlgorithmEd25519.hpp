//
//  CryptoAlgorithmEd25519.hpp
//  WebCore
//
//  Created by Ángela Izquierdo García on 5/9/22.
//

#pragma once

#include "CryptoAlgorithm.h"

#if ENABLE(WEB_CRYPTO)
namespace WebCore {

class CryptoAlgorithmEcdsaParams;
class CryptoKeyEC;

class CryptoAlgorithmEd25519 final : public CryptoAlgorithm {
public:
    static constexpr ASCIILiteral s_name = "Ed25519"_s;
    static constexpr CryptoAlgorithmIdentifier s_identifier = CryptoAlgorithmIdentifier::Ed25519;
    static Ref<CryptoAlgorithm> create();

private:
    CryptoAlgorithmEd25519() = default;
    CryptoAlgorithmIdentifier identifier() const final;
    void generateKey(const CryptoAlgorithmParameters& parameters, bool extractable, CryptoKeyUsageBitmap usages, KeyOrKeyPairCallback&& callback, ExceptionCallback&& exceptionCallback, ScriptExecutionContext&) ;
    
    void sign(const CryptoAlgorithmParameters&, Ref<CryptoKey>&&, Vector<uint8_t>&&, VectorCallback&&, ExceptionCallback&&, ScriptExecutionContext&, WorkQueue&) final;
     
    
    void verify(const CryptoAlgorithmParameters&, Ref<CryptoKey>&&, Vector<uint8_t>&& signature, Vector<uint8_t>&&, BoolCallback&&, ExceptionCallback&&, ScriptExecutionContext&, WorkQueue&) final;
   
    void importKey(CryptoKeyFormat, KeyData&&, const CryptoAlgorithmParameters&, bool extractable, CryptoKeyUsageBitmap, KeyCallback&&, ExceptionCallback&&) final;
    void exportKey(CryptoKeyFormat, Ref<CryptoKey>&&, KeyDataCallback&&, ExceptionCallback&&) final;
     
    
    static ExceptionOr<Vector<uint8_t>> platformSign(const CryptoAlgorithmEcdsaParams&, const CryptoKeyEC&, const Vector<uint8_t>&);
    static ExceptionOr<bool> platformVerify(const CryptoAlgorithmEcdsaParams&, const CryptoKeyEC&, const Vector<uint8_t>&, const Vector<uint8_t>&);
    
};

}
#endif /* CryptoAlgorithmEd25519_hpp */
