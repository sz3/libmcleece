#pragma once

#include "mcleece/actions.h"
#include "serialize/format.h"
#include "util/File.h"
#include <filesystem>
#include <string>

namespace TestHelpers
{
	inline void generate_keypair(std::filesystem::path target_prefix, int mode=mcleece::SIMPLE)
	{
		std::string basename = std::filesystem::path(target_prefix).filename();
		std::string path = std::filesystem::temp_directory_path() / basename;
		std::string pk = fmt::format("{}.pk", path);
		std::string sk = fmt::format("{}.sk", path);
		if (!File(pk).good() or !File(sk).good())
			mcleece::actions::keypair_to_file(path, "password", mode);

		std::filesystem::copy(pk, target_prefix.replace_extension(".pk"));
		std::filesystem::copy(sk, target_prefix.replace_extension(".sk"));
	}
}

