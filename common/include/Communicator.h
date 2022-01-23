#pragma once
#include <string>
#include <sys/socket.h>
#include <stdexcept>
#include <memory>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <cerrno>
#include <cstring>
#include <iostream>

#define MAX_RECV_BUF_SIZE (1024)

#define SSL_CERT_COUNTRY_CODE ("IL")
#define SSL_CERT_ORGANIZATION ("Very-Real-Company")
#define SSL_CERT_COMMON_NAME ("localhost")

class Communicator
{
private:
    int _comm_socket;
    SSL* _cSSL;
    SSL_CTX* _ssl_ctx;

    void initialize_ssl();
    void shutdown_ssl();
    void create_certificate(const char* cert_path, const char* pkey_path);
    
public:
    Communicator(int comm_socket, const SSL_METHOD* method, const char* cert_path, const char* pkey_path);
    ~Communicator();

    void send(std::string msg);
    std::string recv();
};
