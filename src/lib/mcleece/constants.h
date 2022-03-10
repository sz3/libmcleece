/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "mceliece6960119f/crypto_kem.h"
#include "sodium/crypto_box.h"

namespace mcleece {

static constexpr int SIMPLE = 0;
static constexpr int CBOX = 1;
static constexpr int SODIUM = 2;

static constexpr unsigned SIMPLE_PUBLIC_KEY_SIZE = crypto_kem_PUBLICKEYBYTES;
static constexpr unsigned SODIUM_PUBLIC_KEY_SIZE = crypto_box_PUBLICKEYBYTES;
static constexpr unsigned CBOX_PUBLIC_KEY_SIZE = SIMPLE_PUBLIC_KEY_SIZE + SODIUM_PUBLIC_KEY_SIZE;

static constexpr unsigned SIMPLE_SECRET_KEY_SIZE = crypto_kem_SECRETKEYBYTES;
static constexpr unsigned CBOX_SECRET_KEY_SIZE = SIMPLE_SECRET_KEY_SIZE + crypto_box_SECRETKEYBYTES;

}
