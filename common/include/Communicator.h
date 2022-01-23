#pragma once
#include <string>
#include <sys/socket.h>
#include <stdexcept>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_RECV_BUF_SIZE (1024)

class Communicator
{
private:
    int _comm_socket;
    SSL* _cSSL;
    SSL_CTX* _ssl_ctx;

    void initialize_ssl();
    void shutdown_ssl();
    
public:
    Communicator(int comm_socket);
    ~Communicator();

    void send(std::string msg);
    std::string recv();
};
