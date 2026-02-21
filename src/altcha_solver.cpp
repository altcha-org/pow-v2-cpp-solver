#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <stdexcept>
#include <charconv>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <argon2.h>
#include "../include/json.hpp"

using json = nlohmann::json;

struct ChallengeParameters {
    std::string algorithm;
    std::string nonce;
    std::string salt;
    int cost;
    int keyLength;
    std::string keyPrefix;
    
    int memoryCost;
    int parallelism;

    long long expiresAt;
    json data;

    static ChallengeParameters from_json(const json& j) {
        ChallengeParameters p;
        p.algorithm = j.at("algorithm").get<std::string>();
        p.nonce = j.at("nonce").get<std::string>();
        p.salt = j.at("salt").get<std::string>();
        p.cost = j.at("cost").get<int>();
        p.keyLength = j.at("keyLength").get<int>();
        p.keyPrefix = j.at("keyPrefix").get<std::string>();
        
        p.expiresAt = j.count("expiresAt") ? j.at("expiresAt").get<long long>() : 0;
        p.data = j.count("data") ? j.at("data") : json({});

        p.memoryCost = j.count("memoryCost") ? j.at("memoryCost").get<int>() : 0;
        p.parallelism = j.count("parallelism") ? j.at("parallelism").get<int>() : 0;

        // Normalize keyPrefix to lowercase
        std::transform(p.keyPrefix.begin(), p.keyPrefix.end(), p.keyPrefix.begin(), ::tolower);

        return p;
    }
};

struct Solution {
    long long counter;
    std::string derivedKeyHex;
    double time;
};

std::vector<unsigned char> hexToBuffer(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::runtime_error("Hex string must have an even length.");
    }
    std::vector<unsigned char> buffer;
    buffer.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        buffer.push_back(static_cast<unsigned char>(std::stoi(byteString, nullptr, 16)));
    }
    return buffer;
}

std::string bufferToHex(const std::vector<unsigned char>& buffer) {
    std::string hex(buffer.size() * 2, ' ');
    const char* hex_digits = "0123456789abcdef";
    for (size_t i = 0; i < buffer.size(); ++i) {
        hex[2 * i] = hex_digits[(buffer[i] >> 4) & 0x0F];
        hex[2 * i + 1] = hex_digits[buffer[i] & 0x0F];
    }
    return hex;
}

double timeDuration(const std::chrono::steady_clock::time_point& start) {
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    return std::floor(duration.count() / 100.0) / 10.0;
}

// --- SHA ---

void deriveKeySHA(
    const ChallengeParameters& parameters,
    const unsigned char* rawSalt,
    size_t rawSaltSize,
    const unsigned char* passwordBuffer,
    size_t passwordSize,
    unsigned char* derivedKeyBuffer
) {
    const EVP_MD* digest;

    if (parameters.algorithm == "SHA-256") {
        digest = EVP_sha256();
    } else if (parameters.algorithm == "SHA-384") {
        digest = EVP_sha384();
    } else if (parameters.algorithm == "SHA-512") {
        digest = EVP_sha512();
    } else {
        throw std::runtime_error("Simple Hash derivation called with unsupported algorithm: " + parameters.algorithm);
    }

    int iterations = (parameters.cost > 0) ? parameters.cost : 1;

    unsigned int digestSize = EVP_MD_size(digest);
    
    std::vector<unsigned char> currentHash(digestSize);
    
    std::vector<unsigned char> message;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("Failed to allocate EVP_MD_CTX");
    }

    try {
        for (int i = 0; i < iterations; ++i) {
            if (i == 0) {
                message.reserve(rawSaltSize + passwordSize);
                message.insert(message.end(), rawSalt, rawSalt + rawSaltSize);
                message.insert(message.end(), passwordBuffer, passwordBuffer + passwordSize);
            } else {
                message = currentHash; 
            }

            if (EVP_DigestInit_ex(ctx, digest, nullptr) != 1) {
                throw std::runtime_error("EVP_DigestInit_ex failed");
            }
            if (EVP_DigestUpdate(ctx, message.data(), message.size()) != 1) {
                throw std::runtime_error("EVP_DigestUpdate failed");
            }
            
            unsigned int hashLen = 0;
            if (EVP_DigestFinal_ex(ctx, currentHash.data(), &hashLen) != 1) {
                throw std::runtime_error("EVP_DigestFinal_ex failed");
            }
            
            if (hashLen != digestSize) {
                 throw std::runtime_error("Unexpected hash length");
            }
        }

        if (static_cast<size_t>(digestSize) < parameters.keyLength) {
             throw std::runtime_error("Requested keyLength (" + std::to_string(parameters.keyLength) + 
                                     ") is larger than the digest output size (" + std::to_string(digestSize) + ")");
        }
        std::copy(currentHash.begin(), currentHash.begin() + parameters.keyLength, derivedKeyBuffer);

    } catch (...) {
        EVP_MD_CTX_free(ctx);
        throw; 
    }
    
    EVP_MD_CTX_free(ctx);
}

// --- PBKDF2 ---

void deriveKeyPBKDF2(
    const ChallengeParameters& parameters,
    const unsigned char* rawSalt,
    size_t rawSaltSize,
    const unsigned char* passwordBuffer,
    size_t passwordSize,
    unsigned char* derivedKeyBuffer
) {
    const EVP_MD* digest;
    
    if (parameters.algorithm == "PBKDF2/SHA-256") {
        digest = EVP_sha256();
    } else if (parameters.algorithm == "PBKDF2/SHA-384") {
        digest = EVP_sha384();
    } else if (parameters.algorithm == "PBKDF2/SHA-512") {
        digest = EVP_sha512();
    } else {
        throw std::runtime_error("PBKDF2 derivation called with unsupported algorithm: " + parameters.algorithm);
    }

    int result = PKCS5_PBKDF2_HMAC(
        reinterpret_cast<const char*>(passwordBuffer),   
        passwordSize,
        rawSalt,                                     
        rawSaltSize,
        parameters.cost, // Iterations
        digest,
        parameters.keyLength,
        derivedKeyBuffer                                     
    );

    if (result != 1) {
        throw std::runtime_error("PBKDF2 derivation failed. OpenSSL Error: " + std::to_string(ERR_get_error()));
    }
}

// --- Scrypt ---

void deriveKeyScrypt(
    const ChallengeParameters& parameters,
    const unsigned char* rawSalt,
    size_t rawSaltSize,
    const unsigned char* passwordBuffer,
    size_t passwordSize,
    unsigned char* derivedKeyBuffer
) {
    // Scrypt context mapping:
    // N (CPU/Memory cost) = parameters.cost
    // r (Block size) = parameters.memoryCost
    // p (Parallelization) = parameters.parallelism
    
    unsigned long long N = parameters.cost;
    unsigned long long r = parameters.memoryCost;
    unsigned long long p = parameters.parallelism;

    // Common defaults
    if (r == 0) r = 8;
    if (p == 0) p = 1;
    
    // Use 1 GB as maxmem, scrypt memory usage: 128 * N * r * p bytes
    const uint64_t MAX_SCRYPT_MEMORY_BYTES = 1073741824ULL;

    int result = EVP_PBE_scrypt(
        reinterpret_cast<const char*>(passwordBuffer),
        passwordSize,
        rawSalt,
        rawSaltSize,
        N,
        r,
        p,
        MAX_SCRYPT_MEMORY_BYTES,
        derivedKeyBuffer,
        parameters.keyLength
    );

    if (result != 1) {
        throw std::runtime_error("Scrypt derivation failed. OpenSSL Error: " + std::to_string(ERR_get_error()));
    }
}


// --- Argon2id ---

void deriveKeyArgon2(
    const ChallengeParameters& parameters,
    const unsigned char* rawSalt,
    size_t rawSaltSize,
    const unsigned char* passwordBuffer,
    size_t passwordSize,
    unsigned char* derivedKeyBuffer
) {
    uint32_t t_cost = parameters.cost;
    uint32_t m_cost = parameters.memoryCost;
    uint32_t parallelism = parameters.parallelism;

    if (parallelism == 0) parallelism = 1;

    int result = argon2id_hash_raw(
        t_cost, 
        m_cost, 
        parallelism, 
        passwordBuffer, passwordSize,
        rawSalt, rawSaltSize,
        derivedKeyBuffer, parameters.keyLength
    );

    if (result != ARGON2_OK) {
        throw std::runtime_error("Argon2 derivation failed: " + std::string(argon2_error_message(result)));
    }
}

void deriveKeyUniversal(
    const ChallengeParameters& parameters,
    const unsigned char* rawSalt,
    size_t rawSaltSize,
    const unsigned char* passwordBuffer,
    size_t passwordSize,
    unsigned char* derivedKeyBuffer
) {
    const std::string& alg = parameters.algorithm;

    if (alg == "SHA-256" || alg == "SHA-384" || alg == "SHA-512") {
        deriveKeySHA(parameters, rawSalt, rawSaltSize, passwordBuffer, passwordSize, derivedKeyBuffer);
    } else if (alg.rfind("PBKDF2/SHA-", 0) == 0) {
        deriveKeyPBKDF2(parameters, rawSalt, rawSaltSize, passwordBuffer, passwordSize, derivedKeyBuffer);
    } else if (alg == "SCRYPT") {
        deriveKeyScrypt(parameters, rawSalt, rawSaltSize, passwordBuffer, passwordSize, derivedKeyBuffer);
    } else if (alg == "ARGON2ID") {
        deriveKeyArgon2(parameters, rawSalt, rawSaltSize, passwordBuffer, passwordSize, derivedKeyBuffer);
    } else {
        throw std::runtime_error("Unsupported Key Derivation Function (KDF) algorithm: " + alg);
    }
}


std::atomic<bool> solution_found(false);
Solution global_solution;
std::mutex solution_mutex;


void solveChallengeWorker(
    const ChallengeParameters& parameters,
    long long counterStart,
    int counterStep,
    int thread_id
) {
    const auto start_time = std::chrono::steady_clock::now();
    
    const std::vector<unsigned char> rawSaltVec = hexToBuffer(parameters.salt);
    const unsigned char* rawSalt = rawSaltVec.data();
    const size_t rawSaltSize = rawSaltVec.size();
    
    const std::vector<unsigned char> rawNonceVec = hexToBuffer(parameters.nonce);
    const unsigned char* rawNonce = rawNonceVec.data();
    const size_t rawNonceSize = rawNonceVec.size();

    const std::string keyPrefix = parameters.keyPrefix;
    long long counter = counterStart;
    
    const size_t COUNTER_SIZE = 4; 
    std::vector<unsigned char> passwordBufferVec(rawNonceSize + COUNTER_SIZE);
    unsigned char* passwordBuffer = passwordBufferVec.data();

    std::copy(rawNonce, rawNonce + rawNonceSize, passwordBuffer);
    
    std::vector<unsigned char> derivedKeyVec(parameters.keyLength);
    unsigned char* derivedKeyBuffer = derivedKeyVec.data();

    while (!solution_found.load(std::memory_order_relaxed)) {
        try {
            uint32_t counterVal = static_cast<uint32_t>(counter);
            size_t offset = rawNonceSize;

            // Big Endian packing
            passwordBuffer[offset + 0] = (counterVal >> 24) & 0xFF;
            passwordBuffer[offset + 1] = (counterVal >> 16) & 0xFF;
            passwordBuffer[offset + 2] = (counterVal >> 8)  & 0xFF;
            passwordBuffer[offset + 3] =  counterVal        & 0xFF;
            
            size_t passwordSize = rawNonceSize + COUNTER_SIZE;

            deriveKeyUniversal(
                parameters,
                rawSalt,
                rawSaltSize,
                passwordBuffer,
                passwordSize,
                derivedKeyBuffer
            );

            std::string derivedKeyHex = bufferToHex(derivedKeyVec);

            if (derivedKeyHex.rfind(keyPrefix, 0) == 0) {
                solution_found.store(true, std::memory_order_relaxed);

                std::lock_guard<std::mutex> lock(solution_mutex);
                global_solution = {
                    counter,
                    derivedKeyHex,
                    timeDuration(start_time)
                };
                
                std::cout << "\n[Thread " << thread_id << "] Solution found! Counter: " << counter << std::endl;
                break;
            }
            
            counter += counterStep;

        } catch (const std::exception& e) {
            std::cerr << "[Thread " << thread_id << "] Error: " << e.what() << std::endl;
            solution_found.store(true, std::memory_order_relaxed);
            break;  
        }
    }
}

Solution solveChallengeWorkers(
    const ChallengeParameters& parameters, 
    int concurrency
) {
    if (concurrency < 1) concurrency = 1;

    solution_found.store(false);
    
    std::vector<std::thread> workers;
    workers.reserve(concurrency);

    for (int i = -1; i < concurrency - 1; ++i) {
        workers.emplace_back(solveChallengeWorker, 
            std::ref(parameters), 
            (long long)i + 1,
            concurrency, 
            i
        );
    }

    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    if (solution_found.load()) {
        return global_solution;
    } else {
        if (global_solution.counter == 0 && global_solution.time == 0.0) {
            std::cout << "\nChallenge could not be solved or failed due to an error." << std::endl;
        }
        return Solution{0, "", 0.0}; 
    }
}


void handle_error(const char* msg) {
    std::cerr << "Error: " << msg << std::endl;
    exit(EXIT_FAILURE);
}

int main(int argc, char* argv[]) {
    OpenSSL_add_all_algorithms();
    
    if (argc < 2 || argc > 3) {
        std::cerr << "Usage: " << argv[0] << " <challenge_file.json> [num_threads]" << std::endl;
        return EXIT_FAILURE;
    }

    std::string filename = argv[1];
    
    int default_threads = (int)std::thread::hardware_concurrency();
    int num_threads = default_threads > 0 ? default_threads : 1; 
    int max_threads = 16; 

    if (argc == 3) {
        try {
            num_threads = std::stoi(argv[2]);
            if (num_threads < 1) {
                num_threads = default_threads;
            }
            num_threads = std::min(num_threads, max_threads); 
        } catch (const std::exception& e) {
            std::cerr << "Invalid number of threads. Using default: " << num_threads << "." << std::endl;
        }
    }
    
    std::cout << "Challenge File: " << filename << std::endl;
    std::cout << "Threads: " << num_threads << " (Hardware Concurrency: " << default_threads << ")" << std::endl;
    std::cout << "----------------------------------------------------" << std::endl;

    std::ifstream file(filename);
    if (!file.is_open()) {
        handle_error("Could not open JSON file.");
    }

    json j;
    try {
        file >> j;
    } catch (const json::parse_error& e) {
        std::cerr << "JSON Parse Error: " << e.what() << "\nFile Content:\n" << std::endl;
        return EXIT_FAILURE;
    }

    if (!j.contains("parameters")) {
        handle_error("JSON file must contain a 'parameters' object.");
    }
    
    ChallengeParameters params;
    try {
        params = ChallengeParameters::from_json(j.at("parameters"));
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse challenge parameters: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    
    std::cout << "Parameters Loaded:\n"
              << "  Algorithm: " << params.algorithm << "\n"
              << "  Cost: " << params.cost << "\n";
    
    if (params.algorithm == "ARGON2ID") {
        std::cout << "  Memory Cost (KB): " << params.memoryCost << "\n"
                  << "  Parallelism: " << params.parallelism << "\n";
    } else if (params.algorithm == "SCRYPT") {
        std::cout << "  Block Size: " << params.memoryCost << "\n"
                  << "  Parallelism: " << params.parallelism << "\n";
    }


    std::cout << "  Nonce: " << params.nonce << "\n"
              << "  Salt: " << params.salt << "\n"
              << "  Required Prefix: " << params.keyPrefix << "\n"
              << "  Key Length (bytes): " << params.keyLength << "\n"
              << "----------------------------------------------------" << std::endl;

    Solution result = solveChallengeWorkers(params, num_threads);

    if (result.counter >= 0) {
        std::cout << "\nSolution Found!" << std::endl;
        std::cout << "  Counter: " << result.counter << std::endl;
        std::cout << "  Derived Key Hex: " << result.derivedKeyHex << std::endl;
        std::cout << "  Time (ms): " << result.time << std::endl;

    } else {
        std::cout << "\n Challenge Not Solved." << std::endl;
    }

    EVP_cleanup();
    ERR_free_strings();

    return EXIT_SUCCESS;
}