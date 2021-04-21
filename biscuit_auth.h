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


#define BISCUIT_AUTH_MAJOR 1
#define BISCUIT_AUTH_MINOR 0
#define BISCUIT_AUTH_PATCH 0


#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * maximum supported version of the serialization format
 */
#define MAX_SCHEMA_VERSION 1

typedef enum {
  None,
  InvalidArgument,
  InternalError,
  FormatSignatureInvalidFormat,
  FormatSignatureInvalidSignature,
  FormatSealedSignature,
  FormatEmptyKeys,
  FormatUnknownPublickKey,
  FormatDeserializationError,
  FormatSerializationError,
  FormatBlockDeserializationError,
  FormatBlockSerializationError,
  FormatVersion,
  InvalidAuthorityIndex,
  InvalidBlockIndex,
  SymbolTableOverlap,
  MissingSymbols,
  Sealed,
  LogicInvalidAuthorityFact,
  LogicInvalidAmbientFact,
  LogicInvalidBlockFact,
  LogicInvalidBlockRule,
  LogicFailedChecks,
  LogicVerifierNotEmpty,
  LogicDeny,
  LogicNoMatchingPolicy,
  ParseError,
  TooManyFacts,
  TooManyIterations,
  Timeout,
  ConversionError,
} ErrorKind;

typedef struct Biscuit Biscuit;

typedef struct BiscuitBuilder BiscuitBuilder;

typedef struct BlockBuilder BlockBuilder;

typedef struct KeyPair KeyPair;

typedef struct PublicKey PublicKey;

/**
 * used to check authorization policies on a token
 *
 * can be created from [`Biscuit::verify`](`crate::token::Biscuit::verify`) or [`Verifier::new`]
 */
typedef struct Verifier Verifier;

const char *error_message(void);

ErrorKind error_kind(void);

uint64_t error_check_count(void);

uint64_t error_check_id(uint64_t check_index);

uint64_t error_check_block_id(uint64_t check_index);

/**
 * deallocation is handled by Biscuit
 * the string is overwritten on each call
 */
const char *error_check_rule(uint64_t check_index);

bool error_check_is_verifier(uint64_t check_index);

KeyPair *key_pair_new(const uint8_t *seed_ptr, uintptr_t seed_len);

PublicKey *key_pair_public(const KeyPair *kp);

/**
 * expects a 32 byte buffer
 */
uintptr_t key_pair_serialize(const KeyPair *kp, uint8_t *buffer_ptr);

/**
 * expects a 32 byte buffer
 */
KeyPair *key_pair_deserialize(uint8_t *buffer_ptr);

void key_pair_free(KeyPair *_kp);

/**
 * expects a 32 byte buffer
 */
uintptr_t public_key_serialize(const PublicKey *kp, uint8_t *buffer_ptr);

/**
 * expects a 32 byte buffer
 */
PublicKey *public_key_deserialize(uint8_t *buffer_ptr);

void public_key_free(PublicKey *_kp);

BiscuitBuilder *biscuit_builder(const KeyPair *key_pair);

bool biscuit_builder_set_authority_context(BiscuitBuilder *builder, const char *context);

bool biscuit_builder_add_authority_fact(BiscuitBuilder *builder, const char *fact);

bool biscuit_builder_add_authority_rule(BiscuitBuilder *builder, const char *rule);

bool biscuit_builder_add_authority_check(BiscuitBuilder *builder, const char *check);

Biscuit *biscuit_builder_build(const BiscuitBuilder *builder,
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

uintptr_t biscuit_block_count(const Biscuit *biscuit);

uintptr_t biscuit_block_fact_count(const Biscuit *biscuit, uint32_t block_index);

uintptr_t biscuit_block_rule_count(const Biscuit *biscuit, uint32_t block_index);

uintptr_t biscuit_block_check_count(const Biscuit *biscuit, uint32_t block_index);

char *biscuit_block_fact(const Biscuit *biscuit, uint32_t block_index, uint32_t fact_index);

char *biscuit_block_rule(const Biscuit *biscuit, uint32_t block_index, uint32_t rule_index);

char *biscuit_block_check(const Biscuit *biscuit, uint32_t block_index, uint32_t check_index);

char *biscuit_block_context(const Biscuit *biscuit, uint32_t block_index);

BlockBuilder *biscuit_create_block(const Biscuit *biscuit);

Biscuit *biscuit_append_block(const Biscuit *biscuit,
                              const BlockBuilder *block_builder,
                              const KeyPair *key_pair,
                              const uint8_t *seed_ptr,
                              uintptr_t seed_len);

Verifier *biscuit_verify(const Biscuit *biscuit, const PublicKey *root);

void biscuit_free(Biscuit *_biscuit);

bool block_builder_set_context(BlockBuilder *builder, const char *context);

bool block_builder_add_fact(BlockBuilder *builder, const char *fact);

bool block_builder_add_rule(BlockBuilder *builder, const char *rule);

bool block_builder_add_check(BlockBuilder *builder, const char *check);

void block_builder_free(BlockBuilder *_builder);

bool verifier_add_fact(Verifier *verifier, const char *fact);

bool verifier_add_rule(Verifier *verifier, const char *rule);

bool verifier_add_check(Verifier *verifier, const char *check);

bool verifier_verify(Verifier *verifier);

char *verifier_print(Verifier *verifier);

void verifier_free(Verifier *_verifier);

void string_free(char *ptr);

const char *biscuit_print(const Biscuit *biscuit);

extern double performance_now(void);

#endif /* biscuit_bindings_h */
