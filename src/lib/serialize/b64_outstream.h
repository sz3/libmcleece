#pragma once

#include "base64/base.hpp"
#include <array>
#include <string>
#include <vector>

template <typename OUTSTREAM>
class b64_outstream
{
public:
	b64_outstream(OUTSTREAM& stream)
		: _stream(stream)
	{}

	~b64_outstream()
	{
		try {
			flush();
		} catch (const std::exception& e) {}  // it's not the end of the world -- we just failed to write
	}

	b64_outstream& write(const char* data, unsigned length)
	{
		if (length == 0)
		{
			flush();
			return *this;
		}

		if (_eidx)
		{
			unsigned remainder = std::min<unsigned>(_extra.size() - _eidx, length);
			std::copy(data, data+remainder, &_extra[_eidx]);
			data += remainder;
			length -= remainder;

			if (remainder + _eidx == _extra.size())
				flush();
		}

		_eidx = length % 3;
		if (_eidx != 0)
		{
			length -= _eidx;
			std::copy(data+length, data+length+_eidx, _extra.data());
		}

		write_direct(data, length);
		return *this;
	}

	b64_outstream& operator<<(const std::string& buffer)
	{
		return write(buffer.data(), buffer.size());
	}

	bool flush()
	{
		if (!_eidx)
			return false;

		int res = write_direct(_extra.data(), _eidx);
		_eidx = 0;
		return res;
	}

protected:
	int write_direct(const char* data, unsigned length)
	{
		std::string encoded = base64::encode(std::string(data, length));
		_stream.write(encoded.data(), encoded.size());
		return encoded.size();
	}

protected:
	OUTSTREAM& _stream;
	std::array<char, 3> _extra;
	unsigned _eidx = 0;
};
