# 🔐 C++ Password Manager

## 📌 Overview
The **C++ Password Manager** is a lightweight command-line application designed to securely generate, organize, and manage passwords. It supports random password generation, file-based storage, categorization, and essential password management operations—all implemented in C++.  

This tool provides an efficient way to keep track of your credentials while maintaining flexibility and simplicity.

---

## ✨ Features
- **Random Password Generator** – Create strong, customizable passwords.  
- **Secure File Storage** – Save passwords in a chosen text file using binary representation.  
- **Search Functionality** – Find passwords quickly using keywords or categories.  
- **Password Management** – Add, edit, delete, and update stored passwords.  
- **Sorting Options** – Organize passwords alphabetically or by category.  
- **Category Management** – Create and remove categories for better organization.  

---

## ⚙️ Installation
1. Ensure you have a C++ compiler installed (e.g., GCC, Clang, MSVC).  
2. Clone this repository or download the source code as a ZIP file.  
3. If downloaded as a ZIP, extract the contents into your preferred directory.  

---

## 🚀 Usage
1. Open a terminal/command prompt and navigate to the project directory.
2. Install OpenSSL development libraries first
```bash
sudo apt-get update
sudo apt-get install libssl-dev
```
4. Compile the project:  
   ```bash
   g++ -std=c++17 -Wall -Wextra -O2 main.cpp -o password_manager -lssl -lcrypto
   ```  
5. Run the application:  
   ```bash
   ./password_manager
   ```  
6. Select or create a password storage file when prompted.  
7. Use the interactive menu to:  
   - Generate random passwords  
   - Add, edit, delete, or search passwords  
   - Sort entries  
   - Manage categories  
8. All changes will be automatically saved to your selected file.  

---

## 📝 Roadmap / TODO
Planned features and improvements:  
- 🔒 AES-128 Encryption & decryption support for secure file storage.  
- 📊 Enhanced password strength evaluation.  
- 📂 Import/export functionality for password databases.  

---

## 🤝 Contributing
Contributions are always welcome! 🚀  
- Report bugs or suggest features via [Issues](../../issues).  
- Submit improvements through pull requests.  

---

## 📄 License
This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.  
