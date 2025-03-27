#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define PORT 8081
#define RSA_KEYLEN 2048
#define AES_KEYLEN 256
#define BUFFER_SIZE 2048

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

void receivePublicKey(int server_socket, char *pubKey)
{
    int pubKeyLen = recv(server_socket, pubKey, BUFFER_SIZE, 0);
    pubKey[pubKeyLen] = '\0';
    std::cout << "Received Public Key:\n" << pubKey << std::endl;
}

RSA *createRSAFromPublicKey(char *pubKey)
{
    BIO *bio = BIO_new_mem_buf(pubKey, -1);
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!rsa)
        handleErrors();
    BIO_free(bio);
    return rsa;
}

void sendSymmetricKey(int server_socket, RSA *rsa, unsigned char *aes_key)
{
    unsigned char encrypted_key[RSA_size(rsa)];
    if (RSA_public_encrypt(crypto_secretbox_KEYBYTES, aes_key, encrypted_key, rsa, RSA_PKCS1_OAEP_PADDING) == -1)
    {
        handleErrors();
    }
    send(server_socket, encrypted_key, sizeof(encrypted_key), 0);

    std::cout << "Sent AES Key: ";
    for (int i = 0; i < crypto_secretbox_KEYBYTES; i++)
        printf("%02x", aes_key[i]);
    std::cout << std::endl;
}

std::string receiveEncryptedMessage(int server_socket, unsigned char *aes_key)
{
    unsigned char iv[crypto_secretbox_NONCEBYTES];
    unsigned char encrypted_message[BUFFER_SIZE + crypto_secretbox_MACBYTES];
    unsigned char decrypted_message[BUFFER_SIZE];
    unsigned long long encrypted_message_len;

    recv(server_socket, iv, sizeof iv, 0);

    encrypted_message_len = recv(server_socket, encrypted_message, sizeof encrypted_message, 0);

    if (crypto_secretbox_open_easy(decrypted_message, encrypted_message, encrypted_message_len, iv, aes_key) != 0)
    {
        handleErrors();
    }

    decrypted_message[encrypted_message_len - crypto_secretbox_MACBYTES] = '\0';
    std::cout << "Received from server: " << decrypted_message << std::endl;
    return std::string(reinterpret_cast<char*>(decrypted_message));
}

void sendEncryptedMessage(int server_socket, unsigned char *aes_key, const char *message)
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

    send(server_socket, iv, sizeof iv, 0);
    send(server_socket, encrypted_message, encrypted_message_len, 0);

    std::cout << "Sent encrypted message: " << message << std::endl;
}

int main()
{
    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    int server_socket;
    struct sockaddr_in server_address;

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <= 0)
    {
        perror("Invalid address/ Address not supported");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (connect(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        perror("Connection failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    char pubKey[BUFFER_SIZE];
    receivePublicKey(server_socket, pubKey);

    RSA *rsa = createRSAFromPublicKey(pubKey);

    unsigned char aes_key[crypto_secretbox_KEYBYTES];
    randombytes_buf(aes_key, sizeof aes_key);

    sendSymmetricKey(server_socket, rsa, aes_key);

    std::string username, password;
    std::cout << "Enter username: ";
    std::getline(std::cin, username);

    sendEncryptedMessage(server_socket, aes_key, username.c_str());

    std::cout << "Enter password: ";
    std::getline(std::cin, password);

    sendEncryptedMessage(server_socket, aes_key, password.c_str());

    std::string response = receiveEncryptedMessage(server_socket, aes_key);

    if (response == "VALID")
    {
        std::cout << "Login successful! Enter commands or 'exit' to quit.\n";
        while (true)
        {
            std::string command;
            std::cout << "> ";
            std::getline(std::cin, command);

            sendEncryptedMessage(server_socket, aes_key, command.c_str());
            if (command == "exit")
                break;

            std::string server_response = receiveEncryptedMessage(server_socket, aes_key);
        }
    }
    else
    {
        std::cerr << "Invalid credentials. Connection closing.\n";
    }

    close(server_socket);
    RSA_free(rsa);

    return 0;
}
