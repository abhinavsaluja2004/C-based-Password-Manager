#ifndef MAIN_H
#define MAIN_H

#include <string>
#include <vector>
#include <memory>

// Forward declaration
class AESCrypto;

struct Password {
    std::string name;
    std::string password;
    std::string category;
    std::string website;
    std::string login;
    
    Password() = default;
};

class PasswordManager {
private:
    std::vector<Password> passwords;
    std::vector<std::string> categories;
    std::string filename;
    std::string masterPassword;
    std::unique_ptr<AESCrypto> crypto;

public:
    PasswordManager(const std::string &file);
    
    void encryptFile();
    void decryptFile();
    bool isPasswordUsed(const std::string &password) const;
    void searchPasswords(const std::string &query) const;
    void sortPasswords(const std::vector<std::string> &fields);
    std::string randomPassword(int length, bool upperCase, bool lowerCase, bool specialChar) const;
    void printVector();
    void addPassword();
    void editPassword();
    void removePassword();
    void addCategory();
    void removeCategory();
};

// Utility function
bool fileExists(const std::string &filename);

#endif // MAIN_H
