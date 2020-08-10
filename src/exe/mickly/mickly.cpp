
#include "mcleece/init_rng.h"
#include "mcleece/public_key.h"
#include "mcleece/private_key.h"
#include "mcleece/mce.h"
#include "mcleece/message.h"
#include "serialize/format.h"

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

	int generate_keypair(string keypath)
	{
		int res = mcleece::generate_keypair(fmt::format("{}.pk", keypath), fmt::format("{}.sk", keypath));
		return res;
	}

	int encrypt(string keypath, string filename)
	{
		mcleece::public_key pubk(keypath);

		mcleece::session_key session = mcleece::generate_session_key(pubk);
		mcleece::nonce n;
		vector<unsigned char> ciphertext = mcleece::encrypt(session, "hello world", n);

		if (use_b64)
		{
			std::string b64session = mcleece::encode_session(session, n);
			std::cout << b64session << std::endl;
			std::cout << std::endl;
			std::string b64c = mcleece::encode(ciphertext);
			std::cout << b64c << std::endl;
		}
		return 0;
	}

	int decrypt(string keypath)
	{
		/*
		mcleece::private_key secret("/tmp/test.sk");
		auto session_nonce = mcleece::decode_session(b64session);
		if (!session_nonce)
			std::cout << "failed decode_session :(" << std::endl;

		std::vector<unsigned char>& enc_session = session_nonce->first;
		mcleece::nonce& enc_n = session_nonce->second;
		vector<unsigned char> rec_ciphertext = mcleece::decode(b64c);

		// decrypt the encrypted key
		mcleece::session_key recoveredSession = mcleece::decode_session_key(secret, enc_session);
		std::string message = mcleece::decrypt(recoveredSession, rec_ciphertext, enc_n);

		std::cout << message << std::endl;*/
		return 0;
	}

	int help(const cxxopts::Options& options, string errormsg="")
	{
		if (errormsg.size())
			std::cout << errormsg << std::endl << std::endl;
		std::cout << options.help() << std::endl;
		return 400;
	}
}

int main(int argc, char** argv)
{
	mcleece::init_rng();

	cxxopts::Options options("mickly", "Encrypt and decrypt using Classic McEliece");

	// password passed on stdin!
	options.add_options()
	    ("command", "encrypt|decrypt|generate-keypair", cxxopts::value<string>())
	    ("i,input", "Input file. For decryption, can be base64 encoded (or not)", cxxopts::value<string>()->default_value(""))
	    ("id", "Identity (basename) of keypair", cxxopts::value<string>()->default_value(""))
	    ("keypair-path", "Path to keypair (default: cwd)", cxxopts::value<string>())
	    ("h,help", "Print usage")
	;
	options.parse_positional({"command", "input"});
	options.show_positional_help();
	options.positional_help("<command> [input]");

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
		return generate_keypair(fmt::format("{}/{}", key_path, id));

	if (command == "encrypt")
	{
		string input = result["input"].as<string>();
		if (input.empty())
			return help(options, "Please specify an input file!");
		if (!exists(input))
			return help(options, "Please specify an input file that exists!");
		return encrypt(fmt::format(key_path));
	}

	else if (command == "decrypt")
	{
		string input = result["input"].as<string>();
		if (input.empty())
			return help(options, "Please specify an input file!");
		if (!exists(input))
			return help(options, "Please specify an input file that exists!");
		return decrypt(fmt::format("{}/{}.sk", key_path, id));
	}

	else
		return help(options, "Please specify a valid command: [encrypt|decrypt|generate-keypair]");

	return 0;
}
