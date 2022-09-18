/*
 * Copyright (C) 2022 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

extern "C" {

#if USE(APPLE_INTERNAL_SDK)
#include <corecrypto/ccec25519.h>
#else

#define CC_SPTR(_sn_, _n_) _n_

#define CC_WIDE_NULL NULL

#define CCRNG_STATE_COMMON \
    int (*CC_SPTR(ccrng_state, generate))(struct ccrng_state *rng, size_t outlen, void *out);

struct ccrng_state {
    CCRNG_STATE_COMMON
};
struct ccrng_state *ccrng(int *error);

#define ccrng_generate(rng, outlen, out) \
    ((rng)->generate((struct ccrng_state *)(rng), (outlen), (out)))

typedef uint8_t ccec25519key[32];
typedef ccec25519key ccec25519secretkey;
typedef ccec25519key ccec25519pubkey;
typedef ccec25519key ccec25519base;

void cccurve25519(ccec25519key out, const ccec25519secretkey sk, const ccec25519base base);
inline void cccurve25519_make_priv(struct ccrng_state *rng, ccec25519secretkey sk)
{
    ccrng_generate(rng, 32, sk);
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
}
inline void cccurve25519_make_pub(ccec25519pubkey pk, const ccec25519secretkey sk)
{
    cccurve25519(pk, sk, CC_WIDE_NULL);
}
inline void cccurve25519_make_key_pair(struct ccrng_state *rng, ccec25519pubkey pk, ccec25519secretkey sk)
{
    cccurve25519_make_priv(rng, sk);
    cccurve25519_make_pub(pk, sk);
}

#endif // USE(APPLE_INTERNAL_SDK)

} // extern "C"
