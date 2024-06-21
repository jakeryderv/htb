#include <chrono>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <sstream>
#include <string>

// compile command: g++ -o "output" "filename".cpp -lssl -lcrypto

// Full character set to include letters, digits, and special characters
const std::string charset = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "0123456789"
                            "!@#$%^&*()-_=+[]{}|;:',.<>?/";

// Function to compute the SHA-256 hash using EVP API
std::string compute_sha256(const std::string &str) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == nullptr) {
    throw std::runtime_error("Failed to create EVP_MD_CTX");
  }

  const EVP_MD *md = EVP_sha256();
  if (md == nullptr) {
    EVP_MD_CTX_free(mdctx);
    throw std::runtime_error("Failed to create EVP_MD");
  }

  if (1 != EVP_DigestInit_ex(mdctx, md, nullptr)) {
    EVP_MD_CTX_free(mdctx);
    throw std::runtime_error("EVP_DigestInit_ex failed");
  }

  if (1 != EVP_DigestUpdate(mdctx, str.c_str(), str.size())) {
    EVP_MD_CTX_free(mdctx);
    throw std::runtime_error("EVP_DigestUpdate failed");
  }

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int lengthOfHash = 0;

  if (1 != EVP_DigestFinal_ex(mdctx, hash, &lengthOfHash)) {
    EVP_MD_CTX_free(mdctx);
    throw std::runtime_error("EVP_DigestFinal_ex failed");
  }

  EVP_MD_CTX_free(mdctx);

  std::stringstream ss;
  for (unsigned int i = 0; i < lengthOfHash; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  }
  return ss.str();
}

// Recursive function to perform brute-force search
bool brute_force_find_suffix(const std::string &known_prefix,
                             const std::string &target_hash,
                             const std::string &known_suffix,
                             std::string &current_suffix, int max_depth) {
  if (max_depth == 0) {
    return false;
  }

  for (char c : charset) {
    std::string candidate = known_prefix + current_suffix + known_suffix + c;
    std::cout << candidate << std::endl;
    if (compute_sha256(candidate) == target_hash) {
      current_suffix += c;
      return true;
    }
    current_suffix += c;
    if (brute_force_find_suffix(known_prefix, target_hash, known_suffix,
                                current_suffix, max_depth - 1)) {
      return true;
    }
    current_suffix.pop_back();
  }
  return false;
}

int main() {
  // var declarations
  std::string known_prefix{""};
  std::string known_suffix{""};
  std::string target_hash{""};
  std::string test{""};

  // prompt for pref/suf/hash
  std::cout << "precompute hash for test: ";
  std::cin >> test;
  std::cout << compute_sha256(test) << std::endl;
  std::cout << "enter known_prefix: ";
  std::cin >> known_prefix;
  std::cout << "enter hash: ";
  std::cin >> target_hash;

  try {
    auto start = std::chrono::high_resolution_clock::now();
    std::string suffix;
    int max_depth =
        1; // Start with adding 1 character and increase incrementally
    bool found = false;

    while (!found &&
           max_depth <= 10) { // Increase depth up to 10 (adjust as needed)
      std::cout << "Trying with max depth: " << max_depth << std::endl;
      suffix.clear();
      found = brute_force_find_suffix(known_prefix, target_hash, known_suffix,
                                      suffix, max_depth);
      max_depth++;
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    if (found) {
      std::cout << "Found the password: "
                << known_prefix + suffix + known_suffix << std::endl;
    } else {
      std::cout << "Password not found within the given range." << std::endl;
    }

    std::cout << "Time taken: " << elapsed.count() << " seconds" << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
  }
  return 0;
}
