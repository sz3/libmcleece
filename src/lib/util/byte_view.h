/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include <algorithm>
#include <string>
#include <string_view>

namespace mcleece {
	struct byte_view : std::basic_string_view<unsigned char>
	{
		using std::basic_string_view<unsigned char>::basic_string_view;

		byte_view(char* data, size_t len)
			: std::basic_string_view<unsigned char>::basic_string_view(reinterpret_cast<unsigned char*>(data), len)
		{}

		byte_view(const char* data, size_t len)
			: mcleece::byte_view(const_cast<char*>(data), len)
		{}

		byte_view(const std::string& buff)
			: mcleece::byte_view(buff.data(), buff.size())
		{}

		template <typename CHAR>
		int write(const CHAR* other, size_t len)
		{
			if (len > this->size())
				len = this->size();

			unsigned char* ours = const_cast<unsigned char*>(this->data());
			std::copy(other, other+len, ours);
			this->advance(len);
			return len;
		}

		bool advance(size_t pos)
		{
			if (pos > this->size())
				pos = this->size();
			*this = {this->data() + pos, this->size() - pos};
			return this->size() != 0;
		}
	};
}
