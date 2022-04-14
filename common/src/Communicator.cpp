#include "Communicator.h"
#include <sys/socket.h>
#include <stdexcept>
#include <memory>
#include <fstream>
#include <iostream>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define MAX_RECV_BUF_SIZE (1024)

#define SSL_CERT_COUNTRY_CODE ("IL")
#define SSL_CERT_ORGANIZATION ("Very-Real-Company")
#define SSL_CERT_COMMON_NAME ("localhost")


void Communicator::initialize_ssl()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

void Communicator::shutdown_ssl()
{
    SSL_shutdown(this->_cSSL);
    SSL_free(this->_cSSL);
    SSL_CTX_free(this->_ssl_ctx);
}

bool Communicator::are_pkey_and_cert_readable(const char* cert_path, const char* pkey_path)
{
    std::ifstream cert_f(cert_path);
    std::ifstream pkey_f(pkey_path);
    return (cert_f.good() && pkey_f.good());
}

Communicator::Communicator(int comm_socket, const SSL_METHOD* method, const char* cert_path, const char* pkey_path)
{
    this->_comm_socket = comm_socket;
    this->initialize_ssl();

    this->_ssl_ctx = SSL_CTX_new(method);
    if (this->_ssl_ctx == NULL)
    {
        throw std::runtime_error("Failed to create SSL context.");
    }

    if (!this->are_pkey_and_cert_readable(cert_path, pkey_path))
    {
        this->create_certificate(cert_path, pkey_path);
    }

    if (SSL_CTX_use_certificate_file(this->_ssl_ctx, cert_path , SSL_FILETYPE_PEM) <= 0)
    {
        throw std::runtime_error("Failed to use certificate file.");
    }

    if (SSL_CTX_use_PrivateKey_file(this->_ssl_ctx, pkey_path, SSL_FILETYPE_PEM) <= 0)
    {
        throw std::runtime_error("Failed to use private key file.");
    }

    this->_cSSL = SSL_new(this->_ssl_ctx);
    if (this->_cSSL == NULL)
    {
        throw std::runtime_error("Failed to create SSL pointer.");
    }

    SSL_set_fd(this->_cSSL, comm_socket);

    // Switch the function, depending if we are the client or the server
    int (*ssl_func)(SSL*);
    if (method == TLS_client_method())
    {
        ssl_func = SSL_connect;
    }
    else if (method == TLS_server_method())
    {
        ssl_func = SSL_accept;
    }
    else
    {
        throw std::runtime_error("Unknown SSL method.");
    }

    if (ssl_func(this->_cSSL) <= 0)
    {
        this->shutdown_ssl();
        throw std::runtime_error("Failed to accept socket.");
    }
}

Communicator::~Communicator()
{
    this->shutdown_ssl();
}

void Communicator::create_certificate(const char* cert_path, const char* pkey_path)
{
    std::cout << "Creating SSL certificate..." << '\n';

    std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> pkey { EVP_PKEY_new(), EVP_PKEY_free };
    if (pkey == NULL)
    {
        throw std::runtime_error("Failed to create a private key.");
    }

    RSA* rsa = RSA_new();
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> bn { BN_new(), BN_free };
    if (BN_set_word(bn.get(), RSA_F4) == 0)
    {
        throw std::runtime_error("Failed to set exponent.");
    }
    if (RSA_generate_key_ex(rsa, 2048, bn.get(), NULL) == 0)
    {
        throw std::runtime_error("Failed to generate RSA key.");
    }
    if (EVP_PKEY_assign_RSA(pkey.get(), rsa) == 0)
    {
        throw std::runtime_error("Failed to assign private key to RSA key.");
    }

    std::unique_ptr<X509, void(*)(X509*)> x509 { X509_new(), X509_free };
    if (x509 == NULL)
    {
        throw std::runtime_error("Failed to create X509 certificate.");
    }

    if (ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1) == 0)
    {
        throw std::runtime_error("Failed to change certificate serial number.");
    }
    if (X509_gmtime_adj(X509_get_notBefore(x509.get()), 0) == NULL)
    {
        throw std::runtime_error("Failed to set certificate valid date.");
    }
    // Valid for 365 days
    if (X509_gmtime_adj(X509_get_notAfter(x509.get()), 31536000L) == NULL)
    {
        throw std::runtime_error("Failed to set certificate valid date.");
    }
    if (X509_set_pubkey(x509.get(), pkey.get()) == 0)
    {
        throw std::runtime_error("Failed to set certificate public key.");
    }

    X509_NAME* name = X509_get_subject_name(x509.get());
    if (name == NULL)
    {
        throw std::runtime_error("Failed to get certificate name.");
    }
    if (X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, 
        (unsigned char*)SSL_CERT_COUNTRY_CODE, -1, -1, 0) == 0)
    {
        throw std::runtime_error("Failed to add x509 entry.");
    }
    if (X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, 
        (unsigned char*)SSL_CERT_ORGANIZATION, -1, -1, 0) == 0)
    {
        throw std::runtime_error("Failed to add x509 entry.");
    }
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
        (unsigned char*)SSL_CERT_COMMON_NAME, -1, -1, 0) == 0)
    {
        throw std::runtime_error("Failed to add x509 entry.");
    }

    if (X509_set_issuer_name(x509.get(), name) == 0)
    {
        throw std::runtime_error("Failed to set issuer name.");
    }
    if (X509_sign(x509.get(), pkey.get(), EVP_sha1()) == 0)
    {
        throw std::runtime_error("Failed to sign the certificate.");
    }

    FILE* f = fopen(pkey_path, "wb");
    if (f == NULL)
    {
        throw std::runtime_error("Failed to open private key file.");
    }
    if (PEM_write_PrivateKey(f, pkey.get(), NULL, NULL, 0, NULL, NULL) == 0)
    {
        throw std::runtime_error("Failed to write private key.");
    }
    fclose(f);

    f = fopen(cert_path, "wb");
    if (f == NULL)
    {
        throw std::runtime_error("Failed to open certificate file.");
    }
    if (PEM_write_X509(f, x509.get()) == 0)
    {
        throw std::runtime_error("Failed to write certificate.");
    }
    fclose(f);
}

void Communicator::send(std::string msg)
{
    if (msg.size() == 0)
    {
        throw std::runtime_error("Can't send empty message.");
    }
    
    const char* data = msg.c_str();
    if (SSL_write(this->_cSSL, data, msg.size()) <= 0)
    {
        throw std::runtime_error("Failed to send message. (Socket closed)");
    }
}

std::string Communicator::recv()
{
    char buf[MAX_RECV_BUF_SIZE] = {0};

    ssize_t bytes_received = SSL_read(this->_cSSL, buf, MAX_RECV_BUF_SIZE);
    if (bytes_received <= 0)
    {
        throw std::runtime_error("Failed to receive message. (Socket closed)");
    }
    buf[bytes_received] = '\0';

    return std::string(buf, bytes_received);
}
