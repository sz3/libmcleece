
#include "mcleece/actions.h"
#include "mcleece/init_rng.h"

#include "cxxopts/cxxopts.hpp"
#include <iostream>
#include <fstream>
#include <random>
#include <unistd.h>
#include <vector>
using std::string;
using std::vector;

namespace {
	bool exists(string path)
	{
		return access(path.c_str(), F_OK) != -1;
	}

	std::string get_working_path()
	{
	   char temp[1024];
	   return ( getcwd(temp, sizeof(temp))? string(temp) : "" );
	}

	int help(const cxxopts::Options& options, string errormsg="")
	{
		if (errormsg.size())
			std::cout << errormsg << std::endl << std::endl;
		std::cout << options.help() << std::endl;
		return 100;
	}
}

int main(int argc, char** argv)
{
	mcleece::init_rng();

	cxxopts::Options options("mickly", "Encrypt and decrypt using Classic McEliece");

	// password passed on stdin!
	options.add_options()
	    ("command", "encrypt|decrypt|generate-keypair", cxxopts::value<string>())
	    ("i,input", "Input file. Required for [encrypt|decrypt]", cxxopts::value<string>()->default_value(""))
	    ("o,output", "Output file. No value -> stdout.", cxxopts::value<string>()->default_value(""))
	    ("id", "Identity (basename) of keypair", cxxopts::value<string>()->default_value(""))
	    ("keypair-path", "Path to keypair (default: cwd)", cxxopts::value<string>())
	    ("base64", "For encryption, base64 encode outputs. For decryption, base64 decode inputs.", cxxopts::value<bool>())
	    ("h,help", "Print usage")
	;
	options.parse_positional({"command", "input", "output"});
	options.show_positional_help();
	options.positional_help("<command> [input] [output]");

	auto result = options.parse(argc, argv);
	if (result.count("help") or !result.count("command"))
		return help(options);

	string key_path = get_working_path();
	if (result.count("keypair-path"))
		key_path = result["keypair-path"].as<string>();
	if (key_path.empty() or !exists(key_path))
		return help(options, "Specified keypair-path is not an accessible path!");

	string id = result["id"].as<string>();
	if (id.empty())
		id = "identity";

	string command = result["command"].as<string>();

	if (command == "generate-keypair")
		return mcleece::actions::generate_keypair(fmt::format("{}/{}", key_path, id));

	if (command == "encrypt")
	{
		string input = result["input"].as<string>();
		if (input.empty())
			return help(options, "Please specify an input file!");
		if (!exists(input))
			return help(options, "Please specify an input file that exists!");
		string output = result["output"].as<string>();
		if (output.empty())
			return mcleece::actions::encrypt(fmt::format("{}/{}.pk", key_path, id), input, std::cout);
		else
		{
			std::ofstream f(output, std::ofstream::binary);
			return mcleece::actions::encrypt(fmt::format("{}/{}.pk", key_path, id), input, f);
		}
	}

	else if (command == "decrypt")
	{
		string input = result["input"].as<string>();
		if (input.empty())
			return help(options, "Please specify an input file!");
		if (!exists(input))
			return help(options, "Please specify an input file that exists!");

		string output = result["output"].as<string>();
		if (output.empty())
			return mcleece::actions::decrypt(fmt::format("{}/{}.sk", key_path, id), input, std::cout);
		else
		{
			std::ofstream f(output, std::ofstream::binary);
			return mcleece::actions::decrypt(fmt::format("{}/{}.sk", key_path, id), input, f);
		}
	}

	else
		return help(options, "Please specify a valid command: [encrypt|decrypt|generate-keypair]");

	return 0;
}
