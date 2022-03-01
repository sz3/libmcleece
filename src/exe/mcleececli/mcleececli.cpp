/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */

#include "mcleece/mcleece.h"
#include "serialize/format.h"

#include "cxxopts/cxxopts.hpp"
extern "C" {
#include "getline/get_line.h"
}
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

	std::string parent_path(string path)
	{
		size_t i = path.find_last_of('/');
		if (i == std::string::npos)
			return "";
		return path.substr(0, i);
	}

	std::string get_working_path()
	{
	   char temp[1024];
	   return ( getcwd(temp, sizeof(temp))? string(temp) : "" );
	}

	string get_pw()
	{
		string pw;
		pw.resize(100);
		get_password(pw.data(), pw.size(), "Enter secret key password: ");
		return pw.c_str();
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
	cxxopts::Options options("mcleececli", "Encrypt and decrypt using Classic McEliece");

	// password passed on stdin!
	options.add_options()
	    ("command", "encrypt|decrypt|keypair", cxxopts::value<string>())
	    ("k,key-path", "Path to key or keypair (default: {cwd}/identity)", cxxopts::value<string>())
	    ("i,input", "Input file. Required for [encrypt|decrypt]", cxxopts::value<string>()->default_value(""))
	    ("o,output", "Output file. No value -> stdout.", cxxopts::value<string>()->default_value(""))
	    ("s,simple", "Simple mceliece mode. Don't use x25519 cryptobox layer.", cxxopts::value<bool>())
	    ("h,help", "Print usage")
	;
	options.parse_positional({"command", "input", "output"});
	options.show_positional_help();
	options.positional_help("<command> [input] [output]");

	auto result = options.parse(argc, argv);
	if (result.count("help") or !result.count("command"))
		return help(options);

	int mode = result.count("simple")? mcleece_MODE_SIMPLE : mcleece_MODE_CRYPTO_BOX;

	string key_path = fmt::format("{}/{}", get_working_path(), "identity");
	if (result.count("key-path"))
		key_path = result["key-path"].as<string>();

	if (key_path.empty())
		return help(options, "No key-path specified!");

	string command = result["command"].as<string>();

	if (command == "keypair")
	{
		if (!exists(parent_path(key_path)))
			return help(options, "key-path is not a writable prefix!");

		string pw = get_pw();
		return mcleece_keypair_to_file(key_path.data(), key_path.size(), pw.data(), pw.size(), mode);
	}

	if (command == "encrypt")
	{
		if (!exists(key_path + ".pk"))
			return help(options, fmt::format("key-path {}.pk does not exist!", key_path));

		string input = result["input"].as<string>();
		if (input.empty())
			return help(options, "Please specify an input file!");
		if (!exists(input))
			return help(options, "Please specify an input file that exists!");

		string output = result["output"].as<string>();
		if (output.empty())
			return mcleece_encrypt_stdout(key_path.data(), key_path.size(), input.data(), input.size(), mode);
		else
			return mcleece_encrypt_file(key_path.data(), key_path.size(), input.data(), input.size(), output.data(), output.size(), mode);
	}

	else if (command == "decrypt")
	{
		if (!exists(key_path + ".sk"))
			return help(options, fmt::format("key-path {}.sk does not exist!", key_path));

		string input = result["input"].as<string>();
		if (input.empty())
			return help(options, "Please specify an input file!");
		if (!exists(input))
			return help(options, "Please specify an input file that exists!");

		string pw = get_pw();
		string output = result["output"].as<string>();
		if (output.empty())
			return mcleece_decrypt_stdout(key_path.data(), key_path.size(), pw.data(), pw.size(), input.data(), input.size(), mode);
		else
			return mcleece_decrypt_file(key_path.data(), key_path.size(), pw.data(), pw.size(), input.data(), input.size(), output.data(), output.size(), mode);
	}

	else
		return help(options, "Please specify a valid command: [encrypt|decrypt|generate-keypair]");

	return 0;
}
