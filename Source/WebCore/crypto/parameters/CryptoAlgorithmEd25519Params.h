//
//  CryptoAlgorithmEd25519Params.h
//  WebCore
//
//  Created by Ángela Izquierdo García on 9/9/22.
//

#ifndef CryptoAlgorithmEd25519Params_h
#define CryptoAlgorithmEd25519Params_h

#pragma once

#include "CryptoAlgorithmParameters.h"

#if ENABLE(WEB_CRYPTO)

namespace WebCore {

class CryptoAlgorithmEd25519Params final : public CryptoAlgorithmParameters {
public:
    String namedCurve;

    Class parametersClass() const final { return Class::Ed25519Params; }

    CryptoAlgorithmEd25519Params isolatedCopy() const
    {
        CryptoAlgorithmEd25519Params result;
        result.identifier = identifier;
        result.namedCurve = namedCurve.isolatedCopy();

        return result;
    }
};

} // namespace WebCore

SPECIALIZE_TYPE_TRAITS_CRYPTO_ALGORITHM_PARAMETERS(Ed25519Params)

#endif // ENABLE(WEB_CRYPTO)

#endif /* CryptoAlgorithmEd25519Params_h */
