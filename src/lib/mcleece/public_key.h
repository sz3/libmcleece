/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "constants.h"
#include "util/byte_view.h"

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// should this be a template class?
// one that manages a vec, and one that uses a byte_view?

namespace mcleece {

template <int MODE>
class public_key
{
public:
	static constexpr unsigned size()
	{
		if (MODE == SIMPLE)
			return SIMPLE_PUBLIC_KEY_SIZE;
		else
			return CBOX_PUBLIC_KEY_SIZE;
	}

public:
	public_key()
	    : _view(static_cast<unsigned char*>(nullptr), 0)
	    , _data(size())
	{}

	public_key(const unsigned char* data)
	    : _view(data, size())
	{
	}

	static public_key from_file(std::string filename)
	{
		public_key pk;
		pk.load(filename);
		return pk;
	}

	unsigned char* data_write()
	{
		return _data.data();
	}

	const unsigned char* data() const
	{
		if (_view.size())
			return _view.data();
		else
			return _data.data();
	}

	bool save(const std::string& filename) const
	{
		std::ofstream f(filename, std::ios::binary);
		f.write(reinterpret_cast<const char*>(_data.data()), _data.size());
		return true;
	}

	bool load(const std::string& filename)
	{
		std::ifstream f(filename, std::ios::binary);
		f.read(reinterpret_cast<char*>(_data.data()), _data.size());
		return true;
	}

protected:
	const mcleece::byte_view _view;
	std::vector<unsigned char> _data;
};

using public_key_simple = public_key<SIMPLE_PUBLIC_KEY_SIZE>;
using public_key_cbox = public_key<CBOX_PUBLIC_KEY_SIZE>;

}
