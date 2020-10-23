/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "base64/base.hpp"
#include <array>
#include <string>
#include <vector>

template <typename INSTREAM>
class b64_instream
{
public:
	b64_instream(INSTREAM& stream)
		: _stream(stream)
	{}

	operator bool() const
	{
		return good();
	}

	bool good() const
	{
		return _stream.good();
	}

	std::streamsize gcount() const
	{
		return _readBytes;
	}

	b64_instream& read(char* decodeBuff, unsigned length)
	{
		_readBytes = 0;
		while (good() && length > 0)
		{
			unsigned maxRead = std::min<unsigned>(length * 4 / 3, _buffer.size());
			_stream.read(_buffer.data(), maxRead);
			unsigned readLen = _stream.gcount();

			std::string decoded = base64::decode(std::string(_buffer.data(), readLen));
			std::copy(decoded.data(), decoded.data() + decoded.size(), decodeBuff);

			_readBytes += decoded.size();
			decodeBuff += decoded.size();
			length -= decoded.size();
		}
		return *this;
	}

protected:
	INSTREAM& _stream;
	unsigned _readBytes = 0;
	std::array<char, 8192> _buffer;
};
