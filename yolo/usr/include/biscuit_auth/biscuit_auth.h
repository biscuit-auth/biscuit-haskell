/*
 * Copyright 2020 Clever Cloud
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef biscuit_bindings_h
#define biscuit_bindings_h


#define BISCUIT_AUTH_MAJOR 0
#define BISCUIT_AUTH_MINOR 6
#define BISCUIT_AUTH_PATCH 0


#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Biscuit Biscuit;

typedef struct BiscuitBuilder BiscuitBuilder;

typedef struct BlockBuilder BlockBuilder;

typedef struct KeyPair KeyPair;

typedef struct PublicKey PublicKey;

typedef struct Verifier Verifier;

const char *error_message(void);

KeyPair *keypair_new(const uint8_t *seed_ptr, uintptr_t seed_len);

PublicKey *keypair_public(const KeyPair *kp);

void keypair_free(KeyPair *_kp);

void public_key_free(PublicKey *_kp);

BiscuitBuilder *biscuit_builder(const KeyPair *keypair);

bool biscuit_builder_add_authority_fact(BiscuitBuilder *builder, const char *fact);

bool biscuit_builder_add_authority_rule(BiscuitBuilder *builder, const char *rule);

bool biscuit_builder_add_authority_caveat(BiscuitBuilder *builder, const char *caveat);

Biscuit *biscuit_builder_build(BiscuitBuilder *builder,
                               const uint8_t *seed_ptr,
                               uintptr_t seed_len);

void biscuit_builder_free(BiscuitBuilder *_builder);

Biscuit *biscuit_from(const uint8_t *biscuit_ptr, uintptr_t biscuit_len);

Biscuit *biscuit_from_sealed(const uint8_t *biscuit_ptr,
                             uintptr_t biscuit_len,
                             const uint8_t *secret_ptr,
                             uintptr_t secret_len);

uintptr_t biscuit_serialized_size(const Biscuit *biscuit);

uintptr_t biscuit_sealed_size(const Biscuit *biscuit);

uintptr_t biscuit_serialize(const Biscuit *biscuit, uint8_t *buffer_ptr);

uintptr_t biscuit_serialize_sealed(const Biscuit *biscuit,
                                   const uint8_t *secret_ptr,
                                   uintptr_t secret_len,
                                   uint8_t *buffer_ptr);

BlockBuilder *biscuit_create_block(const Biscuit *biscuit);

Verifier *biscuit_verify(const Biscuit *biscuit, const PublicKey *root);

void biscuit_free(Biscuit *_biscuit);

bool block_builder_add_fact(BlockBuilder *builder, const char *fact);

bool block_builder_add_rule(BlockBuilder *builder, const char *rule);

bool block_builder_add_caveat(BlockBuilder *builder, const char *caveat);

void block_builder_free(BlockBuilder *_builder);

bool verifier_add_fact(Verifier *verifier, const char *fact);

bool verifier_add_rule(Verifier *verifier, const char *rule);

bool verifier_add_caveat(Verifier *verifier, const char *caveat);

bool verifier_verify(Verifier *verifier);

char *verifier_print(Verifier *verifier);

void verifier_free(Verifier *_verifier);

void string_free(char *ptr);

#endif /* biscuit_bindings_h */
