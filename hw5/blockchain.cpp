#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>

enum InputType { text, hex };

std::string hex2bytes(const std::string& hex) {
    std::string bytes;
    CryptoPP::StringSource(hex, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(bytes)));
    return bytes;
}

std::string sha256(const std::string &input)
{
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource(input, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    return digest;
}

bool check_hash(const std::string &input, int n)
{
    bool flag = true;
    for (int i = 0; i < n; i++) {
        if (input[i] != '0') {
            flag = false;
            break;
        }
    }
    return flag;
}

std::string find_n_leading_zeros(const std::string &input, int n, std::string &nonce)
{
    std::stringstream ss;
    std::string preimage;
    std::string bytes;
    std::string output;
    preimage.reserve(40);

    unsigned int i;
    unsigned int limit = 0 - 1;
    for (i = 0; i < limit; i++) {
        ss << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << i;
        preimage = input + ss.str();
        bytes = hex2bytes(preimage);
        output = sha256(bytes);
        if (check_hash(output, n) == true) {
            nonce = ss.str();
            break;
        }
        ss.str("");
        ss.clear();
    }

    return output;
}

int main(int argc, char **argv)
{
    std::string initial_message = "Bitcoin";
    std::string prev_hash = sha256(initial_message);
    std::string output;
    std::string nonce;
    int n = 5;
    for (int i = 0; i < n; i++) {
        output = find_n_leading_zeros(prev_hash, i, nonce);
        std::cout << i << std::endl
                  << prev_hash << std::endl
                  << nonce << std::endl
                  << output << std::endl;
        prev_hash = output;
    }

    return 0;
}
