#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <sstream>
#include <string>

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

// Brute-force to find the correct number
std::string brute_force_find_suffix(const std::string &known_prefix,
                                    const std::string &target_hash) {
  for (long long i = 1; i <= 1000000000; ++i) {
    std::string candidate = known_prefix + std::to_string(i);
    std::cout << candidate << std::endl;
    if (compute_sha256(candidate) == target_hash) {
      return candidate;
    }
  }
  return "";
}

int main() {
  // known portion of passwd
  std::string known_prefix;
  // hash of target match
  std::string target_hash;
  // testing functionality purpose(y/n)
  char switch_hash;
  // storing test hash
  std::string test_hash;

  std::cout << "enter part & hash target? (y/n): ";
  std::cin >> switch_hash;
  if (switch_hash == 'y') {
    std::cout << "enter passwd to get test hash: ";
    std::cin >> test_hash;
    std::cout << "hashed= " << compute_sha256(test_hash) << std::endl;
    std::cout << "enter part: ";
    std::cin >> known_prefix;
    std::cout << "enter hash: ";
    std::cin >> target_hash;
  }

  try {
    std::string result = brute_force_find_suffix(known_prefix, target_hash);
    if (!result.empty()) {
      std::cout << "Found the password: " << result << std::endl;
    } else {
      std::cout << "Password not found within the given range." << std::endl;
    }
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
  }
  return 0;
}
