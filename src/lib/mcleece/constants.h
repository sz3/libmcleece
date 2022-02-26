/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "mceliece6960119f/crypto_kem.h"
#include "sodium/crypto_box.h"

namespace mcleece {

static constexpr int SIMPLE = 0;
static constexpr int CBOX = 1;

// probably hide this in a special class?
static constexpr unsigned SIMPLE_PUBLIC_KEY_SIZE = crypto_kem_PUBLICKEYBYTES;
static constexpr unsigned CBOX_PUBLIC_KEY_SIZE = SIMPLE_PUBLIC_KEY_SIZE + crypto_box_PUBLICKEYBYTES;

}
