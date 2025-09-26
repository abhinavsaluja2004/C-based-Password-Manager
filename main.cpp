#include <iostream>
#include <fstream>
#include <vector>
#include <ctime>
#include <algorithm>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "main.h"

// AES helper class for encryption/decryption
class AESCrypto {
private:
    unsigned char key[32]; // 256-bit key
    
public:
    AESCrypto(const std::string& password) {
        // Derive key from password using SHA-256
        SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), 
               password.length(), key);
    }
    
    std::string encrypt(const std::string& plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return "";
        
        // Generate random IV
        unsigned char iv[AES_BLOCK_SIZE];
        if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        // Initialize encryption
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        // Allocate buffer for ciphertext
        int len;
        int ciphertext_len;
        unsigned char* ciphertext = new unsigned char[plaintext.length() + AES_BLOCK_SIZE];
        
        // Encrypt the plaintext
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, 
                            reinterpret_cast<const unsigned char*>(plaintext.c_str()), 
                            plaintext.length()) != 1) {
            delete[] ciphertext;
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        ciphertext_len = len;
        
        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
            delete[] ciphertext;
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        ciphertext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Combine IV and ciphertext
        std::string result;
        result.append(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
        result.append(reinterpret_cast<char*>(ciphertext), ciphertext_len);
        
        delete[] ciphertext;
        return result;
    }
    
    std::string decrypt(const std::string& ciphertext_with_iv) {
        if (ciphertext_with_iv.length() < AES_BLOCK_SIZE) return "";
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return "";
        
        // Extract IV and ciphertext
        unsigned char iv[AES_BLOCK_SIZE];
        memcpy(iv, ciphertext_with_iv.c_str(), AES_BLOCK_SIZE);
        
        const unsigned char* ciphertext = 
            reinterpret_cast<const unsigned char*>(ciphertext_with_iv.c_str() + AES_BLOCK_SIZE);
        int ciphertext_len = ciphertext_with_iv.length() - AES_BLOCK_SIZE;
        
        // Initialize decryption
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        // Allocate buffer for plaintext
        int len;
        int plaintext_len;
        unsigned char* plaintext = new unsigned char[ciphertext_len + AES_BLOCK_SIZE];
        
        // Decrypt the ciphertext
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
            delete[] plaintext;
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        plaintext_len = len;
        
        // Finalize decryption
        if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
            delete[] plaintext;
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        std::string result(reinterpret_cast<char*>(plaintext), plaintext_len);
        delete[] plaintext;
        return result;
    }
};

// Helper functions for serialization
std::string passwordToString(const Password& password) {
    std::ostringstream oss;
    oss << password.name << "|" 
        << password.password << "|" 
        << password.category << "|" 
        << password.website << "|" 
        << password.login << "\n";
    return oss.str();
}

Password stringToPassword(const std::string& str) {
    Password password;
    std::istringstream iss(str);
    std::string token;
    
    if (std::getline(iss, token, '|')) password.name = token;
    if (std::getline(iss, token, '|')) password.password = token;
    if (std::getline(iss, token, '|')) password.category = token;
    if (std::getline(iss, token, '|')) password.website = token;
    if (std::getline(iss, token)) password.login = token;
    
    return password;
}

/**
 * Constructor of the PasswordManager class
 * 
 * @param file The file passed to the constructor, which will be decrypted
 */
PasswordManager::PasswordManager(const std::string &file) : filename(file) {
    // Get master password for encryption/decryption
    std::cout << "Enter master password: ";
    std::getline(std::cin, masterPassword);
    crypto = std::make_unique<AESCrypto>(masterPassword);
    decryptFile();
}

/**
 * Function that saves passwords to a file in encrypted form using AES.
 */
void PasswordManager::encryptFile() {
    std::ofstream file(filename, std::ios::binary);
    if (file.is_open()) {
        // Serialize all passwords to a single string
        std::string allPasswords;
        for (const auto &password : passwords) {
            allPasswords += passwordToString(password);
        }
        
        // Encrypt the serialized data
        std::string encrypted = crypto->encrypt(allPasswords);
        
        if (!encrypted.empty()) {
            file.write(encrypted.c_str(), encrypted.length());
            std::cout << "Passwords saved and encrypted successfully.\n";
        } else {
            std::cout << "Error encrypting data.\n";
        }
        file.close();
    } else {
        std::cout << "Error saving file.\n";
    }
}

/**
 * Function that reads passwords from a file and decrypts them using AES.
 */
void PasswordManager::decryptFile() {
    passwords.clear();
    
    std::ifstream file(filename, std::ios::binary);
    if (file.is_open()) {
        // Read entire encrypted file
        std::string encrypted((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
        file.close();
        
        if (!encrypted.empty()) {
            // Decrypt the data
            std::string decrypted = crypto->decrypt(encrypted);
            
            if (!decrypted.empty()) {
                // Parse the decrypted data
                std::istringstream iss(decrypted);
                std::string line;
                while (std::getline(iss, line) && !line.empty()) {
                    Password password = stringToPassword(line);
                    if (!password.name.empty()) {
                        passwords.push_back(password);
                    }
                }
                std::cout << "Passwords loaded and decrypted successfully.\n";
            } else {
                std::cout << "Error decrypting file. Wrong password?\n";
            }
        }
    } else {
        std::cout << "File doesn't exist or error reading file. Creating new file.\n";
    }
}

/**
 * Check if the password has already been used.
 *
 * @param password The parameter to check if already used
 * @return true if the parameter was already used
 * @return false if the parameter was not used
 */
bool PasswordManager::isPasswordUsed(const std::string &password) const {
    for (const auto &entry: passwords) {
        if (entry.password == password) {
            return true;
        }
    }
    return false;
}

/**
 * Method that searches for a password based on the query provided as an argument.
 */
void PasswordManager::searchPasswords(const std::string &query) const {
    std::cout << "Searched passwords:\n";
    bool found = false;

    for (const auto &password: passwords) {
        if (password.name.find(query) != std::string::npos ||
            password.password.find(query) != std::string::npos ||
            password.category.find(query) != std::string::npos ||
            password.website.find(query) != std::string::npos ||
            password.login.find(query) != std::string::npos) {

            std::cout << "Name: " << password.name << std::endl;
            std::cout << "Password: " << password.password << std::endl;
            std::cout << "Category: " << password.category << std::endl;
            std::cout << "Website: " << password.website << std::endl;
            std::cout << "Login: " << password.login << std::endl;
            std::cout << std::endl;
            found = true;
        }
    }
    
    if (!found) {
        std::cout << "No passwords found matching the query.\n";
    }
}

/**
 * Sort passwords by different parameters.
 */
void PasswordManager::sortPasswords(const std::vector<std::string> &fields) {
    std::vector<Password> result = passwords;

    std::sort(result.begin(), result.end(), [&fields](const Password &firstPasswd, const Password &secondPasswd) -> bool {
        for (const auto &field: fields) {
            if (field == "name") {
                if (firstPasswd.name != secondPasswd.name) {
                    return firstPasswd.name < secondPasswd.name;
                }
            } else if (field == "password") {
                if (firstPasswd.password != secondPasswd.password) {
                    return firstPasswd.password < secondPasswd.password;
                }
            } else if (field == "category") {
                if (firstPasswd.category != secondPasswd.category) {
                    return firstPasswd.category < secondPasswd.category;
                }
            } else if (field == "website") {
                if (firstPasswd.website != secondPasswd.website) {
                    return firstPasswd.website < secondPasswd.website;
                }
            } else if (field == "login") {
                if (firstPasswd.login != secondPasswd.login) {
                    return firstPasswd.login < secondPasswd.login;
                }
            }
        }
        return false;
    });

    std::cout << "Sorted passwords:\n";
    for (const auto &password: result) {
        std::cout << "Name: " << password.name << std::endl;
        std::cout << "Password: " << password.password << std::endl;
        std::cout << "Category: " << password.category << std::endl;
        std::cout << "Website: " << password.website << std::endl;
        std::cout << "Login: " << password.login << std::endl;
        std::cout << std::endl;
    }
}

/**
 * Function that generates a random password.
 */
std::string PasswordManager::randomPassword(int length, bool upperCase, bool lowerCase, bool specialChar) const {
    std::srand(std::time(nullptr));
    const std::string lowerChars = "abcdefghijklmnopqrstuvwxyz";
    const std::string upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string specialChars = "!@#$%^&*()-+=~`;:'?/";

    std::string combinedChars;

    if (upperCase) {
        combinedChars += upperChars;
    }
    if (lowerCase) {
        combinedChars += lowerChars;
    }
    if (specialChar) {
        combinedChars += specialChars;
    }

    if (combinedChars.empty()) {
        return ""; // No character types selected
    }

    std::string result;
    int combinedCharsLength = combinedChars.length();

    for (int i = 0; i < length; i++) {
        int randomIndex = std::rand() % combinedCharsLength;
        result += combinedChars[randomIndex];
    }

    return result;
}

void PasswordManager::printVector() {
    std::cout << "Available categories: " << std::endl;
    for (const auto &category: categories) {
        std::cout << "- " << category << std::endl;
    }
}

/**
 * Function that adds a password with parameters of our choice.
 */
void PasswordManager::addPassword() {
    Password password;
    std::cout << "Adding new password:" << std::endl;

    do {
        std::cout << "Name: ";
        std::getline(std::cin, password.name);
    } while (password.name.empty());

    std::cout << "Do you want to generate a random password? (Y/N): ";
    char generateChoice;
    std::cin >> generateChoice;
    generateChoice = std::tolower(generateChoice);
    std::cin.ignore();

    if (generateChoice == 'y') {
        int length;
        bool includeUppercase, includeLowercase, includeSpecialChars;

        std::cout << "Password length: ";
        std::cin >> length;
        std::cin.ignore();

        std::cout << "Include uppercase letters? (Y/N): ";
        char upperChoice;
        std::cin >> upperChoice;
        std::cin.ignore();
        upperChoice = std::tolower(upperChoice);
        includeUppercase = (upperChoice == 'y');

        std::cout << "Include lowercase letters? (Y/N): ";
        char lowerChoice;
        std::cin >> lowerChoice;
        std::cin.ignore();
        lowerChoice = std::tolower(lowerChoice);
        includeLowercase = (lowerChoice == 'y');

        std::cout << "Include special characters? (Y/N): ";
        char specialChoice;
        std::cin >> specialChoice;
        std::cin.ignore();
        specialChoice = std::tolower(specialChoice);
        includeSpecialChars = (specialChoice == 'y');

        password.password = randomPassword(length, includeUppercase, includeLowercase, includeSpecialChars);
        std::cout << "Generated password: " << password.password << std::endl;
    } else if (generateChoice == 'n') {
        do {
            std::cout << "Password: ";
            std::getline(std::cin, password.password);
            if (isPasswordUsed(password.password)) {
                std::cout << "Password is already used and may be unsafe.\n";
            }
        } while (password.password.empty());
    } else {
        std::cout << "Invalid choice.\n";
        return;
    }

    std::cout << "Do you want to add an already created category? (Y/n): ";
    char categoryChoice;
    std::cin >> categoryChoice;
    categoryChoice = std::tolower(categoryChoice);
    std::cin.ignore();
    
    if (categoryChoice == 'y') {
        if (!categories.empty()) {
            printVector();
            std::cout << "Category: ";
            std::getline(std::cin, password.category);
        } else {
            std::cout << "No categories available. Creating new category.\n";
            std::cout << "Category: ";
            std::getline(std::cin, password.category);
        }
    } else {
        do {
            std::cout << "Category: ";
            std::getline(std::cin, password.category);
        } while (password.category.empty());
        
        // Add to categories if not already present
        if (std::find(categories.begin(), categories.end(), password.category) == categories.end()) {
            categories.push_back(password.category);
        }
    }

    std::cout << "Website (optional): ";
    std::getline(std::cin, password.website);

    std::cout << "Login (optional): ";
    std::getline(std::cin, password.login);

    passwords.push_back(password);
    encryptFile();
    std::cout << "Password added successfully!\n";
}

/**
 * Function that allows the user to change values in a password.
 */
void PasswordManager::editPassword() {
    std::string name;
    std::cout << "Enter name of the password to edit: ";
    std::getline(std::cin, name);

    bool found = false;
    for (auto &password: passwords) {
        if (password.name == name) {
            std::cout << "Editing password: " << password.name << std::endl;

            std::cout << "New name (press enter to keep '" << password.name << "'): ";
            std::string newName;
            std::getline(std::cin, newName);
            if (!newName.empty()) {
                password.name = newName;
            }

            std::cout << "New password (press enter to keep current): ";
            std::string newPassword;
            std::getline(std::cin, newPassword);
            if (!newPassword.empty()) {
                password.password = newPassword;
            }

            std::cout << "New category (press enter to keep '" << password.category << "'): ";
            std::string newCategory;
            std::getline(std::cin, newCategory);
            if (!newCategory.empty()) {
                password.category = newCategory;
            }

            std::cout << "New website (press enter to keep '" << password.website << "'): ";
            std::string newWebsite;
            std::getline(std::cin, newWebsite);
            if (!newWebsite.empty()) {
                password.website = newWebsite;
            }

            std::cout << "New login (press enter to keep '" << password.login << "'): ";
            std::string newLogin;
            std::getline(std::cin, newLogin);
            if (!newLogin.empty()) {
                password.login = newLogin;
            }

            encryptFile();
            std::cout << "Password edited successfully.\n";
            found = true;
            break;
        }
    }

    if (!found) {
        std::cout << "Password not found.\n";
    }
}

/**
 * Function that asks the user for a password name and then deletes it.
 */
void PasswordManager::removePassword() {
    std::string name;
    std::cout << "Enter the name of the password to delete: ";
    std::getline(std::cin, name);

    std::cout << "You are about to delete password '" << name << "'. Are you sure? (Y/N): ";
    char confirmation;
    std::cin >> confirmation;
    confirmation = std::tolower(confirmation);
    std::cin.ignore();

    if (confirmation == 'y') {
        auto it = std::remove_if(passwords.begin(), passwords.end(), 
                                [&name](const Password &password) {
                                    return password.name == name;
                                });

        if (it != passwords.end()) {
            passwords.erase(it, passwords.end());
            encryptFile();
            std::cout << "Password deleted successfully.\n";
        } else {
            std::cout << "Password not found.\n";
        }
    } else {
        std::cout << "Operation canceled.\n";
    }
}

/**
 * Function that adds a new category to the category vector.
 */
void PasswordManager::addCategory() {
    std::string category;
    std::cout << "Enter name of the category: ";
    std::getline(std::cin, category);
    
    if (!category.empty()) {
        if (std::find(categories.begin(), categories.end(), category) == categories.end()) {
            categories.push_back(category);
            std::cout << "Category '" << category << "' added successfully.\n";
        } else {
            std::cout << "Category already exists.\n";
        }
    } else {
        std::cout << "Category name cannot be empty.\n";
    }
}

/**
 * Function that deletes a category along with all passwords assigned to it.
 */
void PasswordManager::removeCategory() {
    std::string category;
    std::cout << "Enter name of the category to delete: ";
    std::getline(std::cin, category);

    std::cout << "This will delete the category and ALL passwords in it. Are you sure? (Y/N): ";
    char confirmation;
    std::cin >> confirmation;
    confirmation = std::tolower(confirmation);
    std::cin.ignore();

    if (confirmation == 'y') {
        // Remove passwords in this category
        auto it = std::remove_if(passwords.begin(), passwords.end(), 
                                [&category](const Password &password) {
                                    return password.category == category;
                                });
        
        size_t removedCount = passwords.end() - it;
        passwords.erase(it, passwords.end());
        
        // Remove category from categories vector
        auto catIt = std::find(categories.begin(), categories.end(), category);
        if (catIt != categories.end()) {
            categories.erase(catIt);
        }
        
        encryptFile();
        std::cout << "Category deleted. " << removedCount << " passwords removed.\n";
    } else {
        std::cout << "Operation canceled.\n";
    }
}

/**
 * Function that checks if the given file exists.
 */
bool fileExists(const std::string &filename) {
    std::ifstream file(filename);
    return file.good();
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    std::string filename;
    int choice;
    std::string query;
    std::vector<std::string> sortFields;
    char input;
    
    std::cout << "=== Secure Password Manager with AES Encryption ===\n";
    std::cout << "Enter name of the file: ";
    std::getline(std::cin, filename);
    std::cout << std::endl;

    PasswordManager manager(filename);

    while (true) {
        std::cout << "\n=== Password Manager Menu ===" << std::endl;
        std::cout << "1. Search password" << std::endl;
        std::cout << "2. Sort password" << std::endl;
        std::cout << "3. Add password" << std::endl;
        std::cout << "4. Edit password" << std::endl;
        std::cout << "5. Delete password" << std::endl;
        std::cout << "6. Add category" << std::endl;
        std::cout << "7. Delete category" << std::endl;
        std::cout << "8. Close program" << std::endl;

        std::cout << "Choose an option (1-8): ";
        std::cin >> choice;
        std::cin.ignore();

        switch (choice) {
            case 1:
                std::cout << "Enter search query: ";
                std::getline(std::cin, query);
                manager.searchPasswords(query);
                std::cout << "\nPress Enter to continue...";
                std::cin.get();
                break;
                
            case 2:
                sortFields.clear();
                std::cout << "Available fields: name, password, category, website, login\n";
                while (true) {
                    std::string field;
                    std::cout << "Enter field to sort by (or 'done' to finish): ";
                    std::getline(std::cin, field);
                    if (field == "done" || field == "q" || field == "Q") {
                        break;
                    }
                    if (field == "name" || field == "password" || field == "category" || 
                        field == "website" || field == "login") {
                        sortFields.push_back(field);
                    } else {
                        std::cout << "Invalid field. Try again.\n";
                    }
                }
                if (!sortFields.empty()) {
                    manager.sortPasswords(sortFields);
                    std::cout << "\nPress Enter to continue...";
                    std::cin.get();
                }
                break;
                
            case 3:
                manager.addPassword();
                break;
                
            case 4:
                manager.editPassword();
                break;
                
            case 5:
                manager.removePassword();
                break;
                
            case 6:
                manager.addCategory();
                break;
                
            case 7:
                manager.removeCategory();
                break;
                
            case 8:
                std::cout << "Goodbye! Your passwords are safely encrypted.\n";
                return 0;
                
            default:
                std::cout << "Invalid option. Please choose 1-8.\n";
                break;
        }
    }
}
