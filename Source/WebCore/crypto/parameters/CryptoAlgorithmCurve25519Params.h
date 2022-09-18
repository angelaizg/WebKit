//
//  CryptoAlgorithmCurve25519Params.h
//  WebCore
//
//  Created by Ángela Izquierdo García on 9/9/22.
//

#ifndef CryptoAlgorithmCurve25519Params_h
#define CryptoAlgorithmCurve25519Params_h



#pragma once

#include "CryptoAlgorithmParameters.h"

#if ENABLE(WEB_CRYPTO)

namespace WebCore {

class CryptoAlgorithmCurve25519Params final : public CryptoAlgorithmParameters {
public:
    String namedCurve;
    std::variant<JSC::Strong<JSC::JSObject>, String> hash;
    CryptoAlgorithmIdentifier hashIdentifier;

    Class parametersClass() const final { return Class::Curve25519Params; }

    CryptoAlgorithmCurve25519Params isolatedCopy() const
    {
        CryptoAlgorithmCurve25519Params result;
        result.identifier = identifier;
        result.hashIdentifier = hashIdentifier;
        result.namedCurve = namedCurve.isolatedCopy();

        return result;
    }
};

} // namespace WebCore

SPECIALIZE_TYPE_TRAITS_CRYPTO_ALGORITHM_PARAMETERS(Curve25519Params)

#endif // ENABLE(WEB_CRYPTO)

#endif /* CryptoAlgorithmCurve25519Params_h */
