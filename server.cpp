#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <mysql/mysql.h>
#include <sstream>
#include <iomanip>
#include <thread>
#include <vector>
#include <array>
#include <unistd.h>
#include <unordered_map>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>

#define PORT 8081
#define RSA_KEYLEN 2048
#define AES_KEYLEN 256
#define BUFFER_SIZE 2048

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

void sendPublicKey(int client_socket, RSA *rsa)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, rsa);
    char *pubKey;
    long pubKeyLen = BIO_get_mem_data(bio, &pubKey);
    std::cout << "Public RSA Key:\n" << std::string(pubKey, pubKeyLen) << std::endl;
    send(client_socket, pubKey, pubKeyLen, 0);
    BIO_free(bio);
}

void receiveSymmetricKey(int client_socket, RSA *rsa, unsigned char *aes_key)
{
    unsigned char encrypted_key[RSA_size(rsa)];
    if (recv(client_socket, encrypted_key, sizeof(encrypted_key), 0) <= 0)
    {
        handleErrors();
    }

    if (RSA_private_decrypt(sizeof(encrypted_key), encrypted_key, aes_key, rsa, RSA_PKCS1_OAEP_PADDING) == -1)
    {
        handleErrors();
    }

    std::cout << "Received AES Key: ";
    for (int i = 0; i < crypto_secretbox_KEYBYTES; i++)
        printf("%02x", aes_key[i]);
    std::cout << std::endl;
}

std::string receiveEncryptedMessage(int client_socket, unsigned char *aes_key)
{
    unsigned char iv[crypto_secretbox_NONCEBYTES];
    unsigned char encrypted_message[BUFFER_SIZE + crypto_secretbox_MACBYTES];
    unsigned char decrypted_message[BUFFER_SIZE];
    unsigned long long encrypted_message_len;

    recv(client_socket, iv, sizeof iv, 0);
    encrypted_message_len = recv(client_socket, encrypted_message, sizeof encrypted_message, 0);

    if (crypto_secretbox_open_easy(decrypted_message, encrypted_message, encrypted_message_len, iv, aes_key) != 0)
    {
        handleErrors();
    }

    decrypted_message[encrypted_message_len - crypto_secretbox_MACBYTES] = '\0';
    std::cout << "Received and decrypted message: " << decrypted_message << std::endl;

    return std::string((char *)decrypted_message);
}

void sendEncryptedMessage(int client_socket, unsigned char *aes_key, const char *message)
{
    unsigned char iv[crypto_secretbox_NONCEBYTES];
    unsigned char encrypted_message[BUFFER_SIZE + crypto_secretbox_MACBYTES];
    unsigned long long encrypted_message_len;

    randombytes_buf(iv, sizeof iv);

    if (crypto_secretbox_easy(encrypted_message, (const unsigned char *)message, strlen(message), iv, aes_key) != 0)
    {
        handleErrors();
    }

    encrypted_message_len = strlen(message) + crypto_secretbox_MACBYTES;

    send(client_socket, iv, sizeof iv, 0);
    send(client_socket, encrypted_message, encrypted_message_len, 0);

    std::cout << "Sent encrypted message: " << message << std::endl;
}

std::string generateSHA256Hash(const std::string &input)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);

    std::ostringstream hashString;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        hashString << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return hashString.str();
}

bool checkCredentials(const std::string &username, const std::string &password)
{
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;

    conn = mysql_init(NULL);
    if (conn == NULL)
    {
        std::cerr << "mysql_init() failed" << std::endl;
        return false;
    }

    if (mysql_real_connect(conn, "localhost", "username", "password", "server", 0, NULL, 0) == NULL)
    {
        std::cerr << "mysql_real_connect() failed: " << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return false;
    }

    std::string query = "SELECT password FROM users WHERE username = '" + username + "'";
    if (mysql_query(conn, query.c_str()))
    {
        std::cerr << "SELECT query failed: " << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return false;
    }

    res = mysql_store_result(conn);
    if (res == NULL)
    {
        std::cerr << "mysql_store_result() failed: " << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return false;
    }

    row = mysql_fetch_row(res);
    if (row == NULL)
    {
        std::cerr << "Username not found!" << std::endl;
        mysql_free_result(res);
        mysql_close(conn);
        return false;
    }

    std::string storedHash = row[0];
    mysql_free_result(res);
    mysql_close(conn);

    std::string inputHash = generateSHA256Hash(password);
    std::cout << inputHash << std::endl;

    if (inputHash == storedHash)
    {
        std::cout << "Credentials validated successfully!" << std::endl;
        return true;
    }
    else
    {
        std::cerr << "Invalid password!" << std::endl;
        return false;
    }
}

std::string trim(const std::string &str) {
    size_t start = str.find_first_not_of(" ");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" ");
    return str.substr(start, end - start + 1);
}

std::vector<std::string> splitByDelimiter(const std::string &input, const std::string &delim) {
    std::vector<std::string> tokens;
    size_t start = 0, end;
    while ((end = input.find(delim, start)) != std::string::npos) {
        tokens.push_back(input.substr(start, end - start));
        start = end + delim.length();
    }
    tokens.push_back(input.substr(start));
    return tokens;
}

bool executeSingleCommand(const std::string &command, std::string &cwd, std::string &output) {
    std::string trimmedCommand = trim(command);

    if (trimmedCommand == "cd") {
        cwd = "/home/tzutzu";
        output += "Directory changed to " + cwd + "\n";
        return true;
    }

    if (trimmedCommand.substr(0, 3) == "cd ") {
        std::string newDir = trim(trimmedCommand.substr(3));
        std::string fullNewDir;

        if (newDir[0] == '/') {
            fullNewDir = newDir;
        } else {
            fullNewDir = cwd + "/" + newDir;
        }

        struct stat info;
        if (stat(fullNewDir.c_str(), &info) != 0 || !(info.st_mode & S_IFDIR)) {
            output += "Error: Directory does not exist.\n";
            return false;
        }
        
        cwd = fullNewDir;
        output += "Directory changed to " + cwd + "\n";
        return true;
    }

    std::string fullCommand;
    if (trimmedCommand[0] == '/') {
        fullCommand = trimmedCommand;
    } else {
        fullCommand = "cd " + cwd + " && " + trimmedCommand;
    }

    FILE *pipe = popen(fullCommand.c_str(), "r");
    if (!pipe) {
        output += "Error executing command: " + trimmedCommand + "\n";
        return false;
    }

    char buffer[128];
    bool outputFound = false;
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        output += buffer;
        outputFound = true;
    }

    int returnCode = pclose(pipe);

    if (returnCode != 0) {
        output += "Command exited with code " + std::to_string(returnCode) + "\n";
    }

    if (!outputFound) {
        output += "No output from command.\n";
    }

    if (!output.empty() && output[output.size() - 1] == '\n') {
        output = output.substr(0, output.size() - 1);
    }

    return true;
}

bool handlePiping(const std::string &command, std::string &cwd, std::string &output) {
    size_t pipePos = command.find('|');
    if (pipePos == std::string::npos) {
        output += "Error: No pipe found in command.\n";
        return false;
    }

    std::string leftCommand = trim(command.substr(0, pipePos));
    std::string rightCommand = trim(command.substr(pipePos + 1));

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        output += "Error: Pipe creation failed.\n";
        return false;
    }

    int outputPipe[2];
    if (pipe(outputPipe) == -1) {
        output += "Error: Output pipe creation failed.\n";
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }

    pid_t leftPid = fork();
    if (leftPid == -1) {
        output += "Error: Fork for left command failed.\n";
        close(pipefd[0]);
        close(pipefd[1]);
        close(outputPipe[0]);
        close(outputPipe[1]);
        return false;
    }

    if (leftPid == 0) {
        close(pipefd[0]);
        close(outputPipe[0]);
        
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        close(outputPipe[1]);

        std::string fullCommand = "cd " + cwd + " && " + leftCommand;
        execl("/bin/sh", "sh", "-c", fullCommand.c_str(), (char *)nullptr);
        _exit(127);
    }

    pid_t rightPid = fork();
    if (rightPid == -1) {
        output += "Error: Fork for right command failed.\n";
        close(pipefd[0]);
        close(pipefd[1]);
        close(outputPipe[0]);
        close(outputPipe[1]);
        kill(leftPid, SIGTERM);
        return false;
    }

    if (rightPid == 0) {
        close(pipefd[1]);
        close(outputPipe[0]);
        
        dup2(pipefd[0], STDIN_FILENO);
        dup2(outputPipe[1], STDOUT_FILENO);
        
        close(pipefd[0]);
        close(outputPipe[1]);

        std::string fullCommand = "cd " + cwd + " && " + rightCommand;
        execl("/bin/sh", "sh", "-c", fullCommand.c_str(), (char *)nullptr);
        _exit(127);
    }

    close(pipefd[0]);
    close(pipefd[1]);
    close(outputPipe[1]);

    char buffer[4096];
    ssize_t bytesRead;
    std::string pipeOutput;
    
    while ((bytesRead = read(outputPipe[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytesRead] = '\0';
        pipeOutput += buffer;
    }
    close(outputPipe[0]);

    int statusLeft, statusRight;
    waitpid(leftPid, &statusLeft, 0);
    waitpid(rightPid, &statusRight, 0);

    if (WIFEXITED(statusLeft) && WEXITSTATUS(statusLeft) == 127) {
        output += "Error: Left command in pipe failed to execute.\n";
        return false;
    }

    if (WIFEXITED(statusRight) && WEXITSTATUS(statusRight) == 127) {
        output += "Error: Right command in pipe failed to execute.\n";
        return false;
    }

    while (!pipeOutput.empty() && std::isspace(pipeOutput.back())) {
        pipeOutput.pop_back();
    }

    output = pipeOutput;

    return true;
}

std::string executeCommand(const std::string &command,
                           std::string &output,
                           std::unordered_map<int, std::string> &clientDirs,
                           int client_socket) {
    std::string cwd = clientDirs[client_socket];
    std::vector<std::string> separators = {";", "&&", "||", "|"};

    size_t pos = 0;
    std::string remainingCommand = command;

    while (!remainingCommand.empty()) {
        size_t minPos = std::string::npos;
        std::string currentSeparator;

        for (const auto &sep : separators) {
            size_t sepPos = remainingCommand.find(sep);
            if (sepPos < minPos) {
                minPos = sepPos;
                currentSeparator = sep;
            }
        }

        if (minPos == std::string::npos) {
            executeSingleCommand(trim(remainingCommand), cwd, output);
            break;
        }

        std::string singleCommand = remainingCommand.substr(0, minPos);
        remainingCommand = remainingCommand.substr(minPos + currentSeparator.length());

        if (currentSeparator == "&&") {
            if (!executeSingleCommand(singleCommand, cwd, output)) {
                break;
            }
        } else if (currentSeparator == "||") {
            if (executeSingleCommand(singleCommand, cwd, output)) {
                break;
            }
        } else if (currentSeparator == "|") {
            if (!handlePiping(trim(singleCommand + " | " + remainingCommand), cwd, output)) {
                break;
            }
            remainingCommand = "";
        } else if (currentSeparator == ";") {
            executeSingleCommand(singleCommand, cwd, output);
        }
    }

    clientDirs[client_socket] = cwd;
    return output;
}

void handleClient(int client_socket, std::unordered_map<int, std::string> &clientDirs) {
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    if (!BN_set_word(bne, RSA_F4))
        handleErrors();
    if (!RSA_generate_key_ex(rsa, RSA_KEYLEN, bne, NULL))
        handleErrors();
    BN_free(bne);

    sendPublicKey(client_socket, rsa);

    unsigned char aes_key[crypto_secretbox_KEYBYTES];
    receiveSymmetricKey(client_socket, rsa, aes_key);

    std::cout << "Receiving encrypted username..." << std::endl;
    std::string username = receiveEncryptedMessage(client_socket, aes_key);

    std::cout << "Receiving encrypted password..." << std::endl;
    std::string password = receiveEncryptedMessage(client_socket, aes_key);

    if (checkCredentials(username, password)) {
        const char *response = "VALID";
        sendEncryptedMessage(client_socket, aes_key, response);

        std::string initialDir = "/home/tzutzu";
        clientDirs[client_socket] = initialDir;

        while (true) {
            std::string command = receiveEncryptedMessage(client_socket, aes_key);
            if (command == "exit")
                break;

            std::string output;
            std::cout << "Executing command in directory: " << clientDirs[client_socket] << std::endl;
            output = executeCommand(command, output, clientDirs, client_socket);
            sendEncryptedMessage(client_socket, aes_key, output.c_str());
        }
    } else {
        const char *response = "INVALID";
        sendEncryptedMessage(client_socket, aes_key, response);
    }

    close(client_socket);
    RSA_free(rsa);
}

int main()
{
    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    int server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0)
    {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    std::unordered_map<int, std::string> clientDirs;
    std::vector<std::thread> threads;

    while (true)
    {
        int client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        if (client_socket < 0)
        {
            perror("accept failed");
            continue;
        }

        threads.emplace_back(handleClient, client_socket, std::ref(clientDirs));
    }

    for (auto &thread : threads)
    {
        if (thread.joinable())
        {
            thread.join();
        }
    }

    close(server_fd);

    return 0;
}
