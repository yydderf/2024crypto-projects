#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <string>
#include <thread>
#include <vector>
#include <atomic>

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

void find_n_leading_zeros_worker(const std::string &input, int n, 
    std::atomic<unsigned int> &counter, std::atomic<bool> &found,
    std::string &nonce, std::string &output)
{
    std::stringstream ss;
    std::string preimage;
    std::string bytes;
    std::string candidate;
    preimage.reserve(40);

    unsigned int i;

    while (!found) {
        i = counter++;
        ss << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << i;
        preimage = input + ss.str();
        bytes = hex2bytes(preimage);
        candidate = sha256(bytes);
        if (check_hash(candidate, n) || i == UINT_MAX) {
            nonce = ss.str();
            output = i == UINT_MAX ? "Not found" : candidate;
            found = true;
            break;
        }
        ss.str("");
        ss.clear();
    }
}

void print_counter(const std::atomic<unsigned int> &counter, const std::atomic<bool> &found)
{
    auto start_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_time;
    while (!found) {
        auto current_time = std::chrono::steady_clock::now();
        elapsed_time = current_time - start_time;
        auto minutes = std::chrono::duration_cast<std::chrono::minutes>(elapsed_time).count();
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed_time).count() % 60;
        std::cout << std::hex << std::uppercase
                  << std::setw(8) << std::setfill('0')
                  << counter.load() << " "
                  << std::dec
                  << std::setw(2) << std::setfill('0')
                  << minutes << ":"
                  << std::setw(2) << std::setfill('0')
                  << seconds << "\r";
    }
}

std::string find_n_leading_zeros(const std::string &input, int n, std::string &nonce, int num_threads = 4)
{
    std::atomic<unsigned int> counter(0);
    std::atomic<bool> found(false);
    std::string output;
    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(find_n_leading_zeros_worker, std::ref(input),
            n, std::ref(counter), std::ref(found), std::ref(nonce), std::ref(output));
    }

    std::thread counter_thread(print_counter, std::ref(counter), std::ref(found));

    for (auto &t: threads) {
        t.join();
    }
    counter_thread.join();

    return output;
}

int main(int argc, char **argv)
{
    std::string initial_message = "109611087";
    std::string prev_hash = sha256(initial_message);
    std::string output;
    std::string nonce;
    std::ofstream ofd("out.txt", std::ios::trunc);
    int num_threads = 4;
    int n = 200;
    for (int i = 0; i < n; i++) {
        i == 0 ? num_threads = 1 : num_threads = 8;
        output = find_n_leading_zeros(prev_hash, i, nonce, num_threads);
        std::cout << i << "                   " << std::endl
                  << prev_hash << std::endl
                  << nonce << std::endl
                  << output << std::endl;
        ofd << i << std::endl
            << prev_hash << std::endl
            << nonce << std::endl
            << output << std::endl;
        prev_hash = output;
    }

    return 0;
}
