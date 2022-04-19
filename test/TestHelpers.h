#pragma once

#include "mcleece/actions.h"
#include "serialize/format.h"
#include "util/File.h"
#include <experimental/filesystem>
#include <string>

namespace TestHelpers
{
	inline void generate_keypair(std::experimental::filesystem::path target_prefix, int mode=mcleece::SIMPLE)
	{
		std::string basename = std::experimental::filesystem::path(target_prefix).filename();
		std::string path = std::experimental::filesystem::temp_directory_path() / basename;
		std::string pk = fmt::format("{}.pk", path);
		std::string sk = fmt::format("{}.sk", path);
		if (!File(pk).good() or !File(sk).good())
			mcleece::actions::keypair_to_file(path, "password", mode);

		std::experimental::filesystem::copy(pk, target_prefix.replace_extension(".pk"));
		std::experimental::filesystem::copy(sk, target_prefix.replace_extension(".sk"));
	}
}

