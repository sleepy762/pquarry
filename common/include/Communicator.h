#pragma once
#include <string>
#include <openssl/ssl.h>

class Communicator
{
private:
    int _comm_socket;
    SSL* _cSSL;
    SSL_CTX* _ssl_ctx;

    void initialize_ssl();
    void shutdown_ssl();
    bool are_pkey_and_cert_readable(const char* cert_path, const char* pkey_path);
    void create_certificate(const char* cert_path, const char* pkey_path);
    
public:
    Communicator(int comm_socket, const SSL_METHOD* method, const char* cert_path, const char* pkey_path);
    ~Communicator();

    void send(std::string msg);
    std::string recv();
};
