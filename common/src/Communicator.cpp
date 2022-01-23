#include "Communicator.h"

void Communicator::initialize_ssl()
{
    // SSL_load_error_strings();
    // SSL_library_init();
    // OpenSSL_add_all_algorithms();
}

void Communicator::shutdown_ssl()
{
    // SSL_shutdown(this->_cSSL);
    // SSL_free(this->_cSSL);
}

Communicator::Communicator(int comm_socket)
{
    this->_comm_socket = comm_socket;
    //this->initialize_ssl();
}

Communicator::~Communicator()
{
    //this->shutdown_ssl();
}

void Communicator::send(std::string msg)
{
    if (msg.size() == 0)
    {
        throw std::runtime_error("Can't send empty message.");
    }
    
    const char* data = msg.c_str();
    if (::send(this->_comm_socket, data, msg.size(), MSG_NOSIGNAL) == -1)
    {
        throw std::runtime_error("Failed to send message. (Socket closed)");
    }
}

std::string Communicator::recv()
{
    char buf[MAX_RECV_BUF_SIZE] = {0};

    ssize_t bytes_received = ::recv(this->_comm_socket, buf, MAX_RECV_BUF_SIZE, 0);
    if (bytes_received <= 0)
    {
        throw std::runtime_error("Failed to receive message. (Socket closed)");
    }
    buf[bytes_received] = '\0';

    return std::string(buf, bytes_received);
}
