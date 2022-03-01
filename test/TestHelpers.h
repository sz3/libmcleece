#pragma once

#include "mcleece/actions.h"
#include "serialize/format.h"
#include "util/File.h"
#include <experimental/filesystem>
#include <string>

namespace TestHelpers
{
	inline bool generate_keypair(std::experimental::filesystem::path target_prefix, int mode=mcleece::SIMPLE)
	{
		std::string basename = std::experimental::filesystem::path(target_prefix).filename();
		std::string pk = std::experimental::filesystem::temp_directory_path() / fmt::format("{}.pk", basename);
		std::string sk = std::experimental::filesystem::temp_directory_path() / fmt::format("{}.sk", basename);
		if (File(pk).good() and File(sk).good())
		{
			std::experimental::filesystem::copy(pk, target_prefix.replace_extension(".pk"));
			std::experimental::filesystem::copy(sk, target_prefix.replace_extension(".sk"));
			return false;
		}
		else
			mcleece::actions::keypair_to_file(target_prefix, "password", mode);
		return true;
	}
}

