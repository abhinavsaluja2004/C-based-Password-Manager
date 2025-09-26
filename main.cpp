#include <iostream>
#include <fstream>
#include <vector>
#include <ctime>
#include <algorithm>
#include "main.h"


/**
 * Function that saves passwords to a file in encrypted form.
 *
 * Uses the write function, which passes binary data.
 *
 */
void PasswordManager::encryptFile() {
    std::ofstream file(filename, std::ios::binary);
    if (file.is_open()) {
        for (const auto &password: passwords) {
            file.write(reinterpret_cast<const char *>(&password), sizeof(password));
        }
        file.close();
    } else {
        std::cout << "Error saving file.\n";
    }
}


/**
 * Function that reads passwords from a file using the read method,
 * which reads binary data.
 */
void PasswordManager::decryptFile() {
    passwords.clear();

    std::ifstream file(filename, std::ios::binary);
    if (file.is_open()) {
        while (!file.eof()) {
            Password password;
            file.read(reinterpret_cast<char *>(&password), sizeof(password));
            if (!file.eof()) {
                passwords.push_back(password);
            }
        }
        file.close();
    } else {
        std::cout << "Error reading file.\n";
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
 * Constructor of the PasswordManager class
 *
 * @param file The file passed to the constructor, which will be decrypted
 */
PasswordManager::PasswordManager(const std::string &file) : filename(file) {
    decryptFile();
}


/**
 * Method that searches for a password based on the query provided as an argument.
 *
 * We use the find() function for std::string with the given query.
 *
 * Then, matching strings from the given categories are displayed.
 *
 * @param query The query under which we want to find our password
 */
void PasswordManager::searchPasswords(const std::string &query) const {
    std::cout << "Searched passwords:\n";

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
        }
    }
}

/**
 * Sort passwords by different parameters.
 *
 * Uses the <algorithm> library and the sort() function.
 *
 * @param fields Choose which parameters to sort by
 * @param result Create a vector with sorted passwords
 * @return false if nothing is found
 */
void PasswordManager::sortPasswords(const std::vector<std::string> &fields) {
    std::vector<Password> result = passwords;

    sort(result.begin(), result.end(), [&fields](const Password &firstPasswd, const Password &secondPasswd) -> bool {
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
 * Function checks which options should be considered when generating a random password.
 *
 * Then generates and returns a random password.
 *
 * @param length password length
 * @param upperCase whether uppercase letters should be included
 * @param lowerCase whether lowercase letters should be included
 * @param specialChar whether special characters should be included
 * @return returns the generated password
 */
std::string PasswordManager::randomPassword(int length, bool upperCase, bool lowerCase, bool specialChar) const {
    srand(time(NULL));
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

    std::string result;

    int combinedCharsLength = combinedChars.length();

    for (int i = 0; i < length; i++) {
        int randomIndex = rand() % combinedCharsLength;
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
 *
 * Allows generating a random password with chosen parameters such as:
 * password length, uppercase letters, lowercase letters, and special characters.
 *
 * After selecting all parameters, creates a password with the appropriate fields
 * and adds it to the vector.
 */
void PasswordManager::addPassword() {
    Password password;
    std::cout << "Adding new password:" << std::endl;

    do {
        std::cout << "Name: ";
        getline(std::cin, password.name);
    } while (password.name.empty());

    std::cout << "Do you want to generate a random password? (Y/N): ";
    char generateChoice;
    std::cin >> generateChoice;
    tolower(generateChoice);
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
        tolower(upperChoice);
        includeUppercase = (upperChoice == 'y');

        std::cout << "Include lowercase letters? (Y/N): ";
        char lowerChoice;
        std::cin >> lowerChoice;
        std::cin.ignore();
        tolower(lowerChoice);
        includeLowercase = (lowerChoice == 'y');

        std::cout << "Include special characters? (Y/N): ";
        char specialChoice;
        std::cin >> specialChoice;
        std::cin.ignore();
        tolower(specialChoice);
        includeSpecialChars = (specialChoice == 'y');

        password.password = randomPassword(length, includeUppercase, includeLowercase, includeSpecialChars);
    } else if (generateChoice == 'n') {
        do {
            std::cout << "Password: ";
            getline(std::cin, password.password);
            if (isPasswordUsed(password.password)) {
                std::cout << "Password is already used and may be unsafe.\n";
            }
        } while (password.password.empty());
    } else {
        std::cout << "Error. \n";
    }

    std::cout << "Do you want to add an already created category? (Y/n): ";
    char categoryChoice;
    std::cin >> categoryChoice;
    tolower(categoryChoice);
    std::cin.ignore();
    if (categoryChoice == 'y') {
        printVector();
        std::cout << "Category: ";
        getline(std::cin, password.category);
    } else {
        do {
            std::cout << "Category: ";
            getline(std::cin, password.category);
        } while (password.category.empty());
    }

    std::cout << "Website (optional): ";
    getline(std::cin, password.website);

    std::cout << "Login (optional): ";
    getline(std::cin, password.login);

    passwords.push_back(password);
    encryptFile();
}

/**
 * Function that allows the user to change values in a password.
 *
 * It asks the user for the password name, then lets the user choose what to edit.
 *
 * @param name password name to edit
 */
void PasswordManager::editPassword() {
    std::string name;
    std::cout << "Enter name of the password to edit: ";
    getline(std::cin, name);

    bool found = false;

    for (auto &password: passwords) {
        if (password.name == name) {
            std::cout << "Editing password:" << std::endl;
            std::cout << "Name: " << password.name << std::endl;

            std::cout << "New name (press enter to keep the same): ";
            getline(std::cin, name);
            if (!name.empty()) {
                password.name = name;
            }

            std::cout << "New password (press enter to keep the same): ";
            getline(std::cin, password.password);

            std::cout << "New category (press enter to keep the same): ";
            getline(std::cin, password.category);

            std::cout << "New website (press enter to keep the same): ";
            getline(std::cin, password.website);

            std::cout << "New login (press enter to keep the same): ";
            getline(std::cin, password.login);

            encryptFile();

            std::cout << "Password edited." << std::endl;
            found = true;
            break;
        }
    }

    if (!found) {
        std::cout << "Password not found." << std::endl;
    }
}

/**
 * Function that asks the user for a password name and then deletes it.
 *
 * @param name name of the password to delete
 */
void PasswordManager::removePassword() {
    std::string name;
    std::cout << "Enter the name of the password to delete: ";
    getline(std::cin, name);

    std::cout << "You are about to delete a password. Are you sure? (Y/N): " << std::endl;
    char confirmation;
    std::cin >> confirmation;
    tolower(confirmation);
    std::cin.ignore();

    if (confirmation == 'y') {
        auto it = remove_if(passwords.begin(), passwords.end(), [&name](const Password &password) {
            return password.name == name;
        });

        if (it != passwords.end()) {
            passwords.erase(it, passwords.end());
            encryptFile();
            std::cout << "Password deleted." << std::endl;
        } else {
            std::cout << "Password not found." << std::endl;
        }
    } else {
        std::cout << "Operation canceled." << std::endl;
    }
}


/**
 * Function that adds a new category to the category vector.
 *
 * Asks the user for the category name
 *
 * @param category name of the category to add
 */
void PasswordManager::addCategory() {
    std::string category;
    std::cout << "Enter name of the category: ";
    getline(std::cin, category);
    categories.push_back(category);

    std::cout << "Category added." << std::endl;
}


/**
 * Function that deletes a category along with all passwords assigned to it.
 *
 * Asks the user for the category name.
 *
 * @param category name of the category to delete
 */
void PasswordManager::removeCategory() {
    std::string category;
    std::cout << "Enter name of the category to delete: ";
    getline(std::cin, category);

    auto it = remove_if(passwords.begin(), passwords.end(), [&category](const Password &password) {
        return password.category == category;
    });
    passwords.erase(it, passwords.end());
    encryptFile();

    std::cout << "Category deleted." << std::endl;


}

/**
 * Function that checks if the given file exists.
 *
 * @param filename file name to check
 * @return true if the file exists
 */
bool fileExists(const std::string &filename) {
    std::ifstream file(filename);
    return file.good();
}

int main() {
    std::string filename;
    int choice;
    std::string query;
    std::vector<std::string> sortFields;
    char input;
    std::cout << "Enter name of the file: ";
    getline(std::cin, filename);
    std::cout << std::endl;

    PasswordManager manager(filename);

    if (!fileExists(filename)) {
        std::cout << "File does not exist.\n";
    } else {
        while (true) {
            std::cout << "1. Search password" << std::endl;
            std::cout << "2. Sort password" << std::endl;
            std::cout << "3. Add password" << std::endl;
            std::cout << "4. Edit password" << std::endl;
            std::cout << "5. Delete password" << std::endl;
            std::cout << "6. Add category" << std::endl;
            std::cout << "7. Delete category" << std::endl;
            std::cout << "8. Close program" << std::endl;

            std::cout << "Choose an option: ";
            std::cin >> choice;
            std::cin.ignore();

            switch (choice) {
                case 1:
                    std::cout << "Enter query: ";
                    getline(std::cin, query);
                    manager.searchPasswords(query);
                    std::cout << "Type q to continue: ";
                    std::cin >> input;
                    tolower(input);
                    if (input == 'q')
                        break;
                case 2:
                    sortFields.clear();
                    while (true) {
                        std::string field;
                        std::cout << "Enter field/fields to sort (type q to close): ";
                        getline(std::cin, field);
                        if (field == "q" || field == "Q") {
                            break;
                        }
                        sortFields.push_back(field);
                    }
                    manager.sortPasswords(sortFields);
                    std::cout << "Type q to continue: ";
                    std::cin >> input;
                    tolower(input);
                    if (input == 'q')
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
                    return 0;
                default:
                    std::cout << "Invalid option." << std::endl;
                    break;
            }
            std::cout << std::endl;
        }
    }
}
