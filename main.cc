#include <asio.hpp>
#include <thread>
#include <memory>
#include <iostream>

using asio::ip::tcp;

class session : public std::enable_shared_from_this<session>
{
public:
    session(tcp::socket socket) :
        socket_(std::move(socket)),
        remote_(socket_.get_executor()),
        resolver_(socket_.get_executor()) {
    }
    void start() {
        do_init_recv();
    }
private:
    // 握手阶段
    void do_init_recv() {
        auto self(shared_from_this());
        socket_.async_read_some(asio::buffer(idata_),
            [this, self](const std::error_code& ec, std::size_t size) {
                if (ec) {
                    return ;
                }
                if (size < 3) {
                    return ;
                }
                if (idata_[0] != 0x05) {
                    return ;
                }
                if (size != 2 + idata_[1]) {
                    return ;
                }

                do_init_send();
            }
        );
    }
    void do_init_send() {
        auto self(shared_from_this());
        asio::async_write(socket_, asio::buffer("\x05\x00", 2),
            [this, self](const std::error_code& ec, std::size_t size) {
                if (!ec) {
                    do_request_recv();
                }
            }
        );
    }
    // 处理请求，仅支持CONNECT，暂不支持IPV6
    void do_request_recv() {
        auto self(shared_from_this());
        socket_.async_read_some(asio::buffer(idata_),
            [this, self](const std::error_code& ec, std::size_t size) {
                if (ec) {
                    return ;
                }
                if (size < 7) {
                    return ;
                }
                if (idata_[0] != 0x05 || idata_[1] != 0x01 || idata_[2] != 0x00) {
                    // REP-0x07 Command not supported
                    return ;
                }
                if (idata_[3] == 0x01 && size != 10 ||
                    idata_[3] == 0x04 && size != 22 ||
                    idata_[3] == 0x03 && size != 7 + idata_[4]) {
                    return ;
                }

                const unsigned char type = idata_[3];
                unsigned short port = idata_[size-2] * 256 + idata_[size-1];

                if (type == 0x01) {
                    tcp::endpoint ep(asio::ip::address_v4({idata_[4], idata_[5], idata_[6], idata_[7]}), port);
                    std::cout << "IPV4ADDR: " << ep << std::endl;

                    do_try_connect(ep);
                }
                else if (type == 0x03) {
                    std::string addr(reinterpret_cast<char*>(&idata_[5]), static_cast<std::size_t>(idata_[4]));

                    resolver_.async_resolve(addr, std::to_string(port), [this, self](const std::error_code& ec, tcp::resolver::results_type results) {
                        for (auto ep : results) {
                            if (ep.endpoint().address().is_v4()) {
                                std::cout << "RESOLVED: " << ep.endpoint() << std::endl;

                                do_try_connect(ep);
                                break;
                            }
                        }
                    });
                }
                else if (type == 0x04) {
                    // REP-0x08 Address type not supported
                    do_request_fail();
                }
            }
        );
    }
    void do_try_connect(tcp::endpoint ep) {
        auto self(shared_from_this());
        remote_.async_connect(ep, [this, self](const std::error_code& ec) {
            if (!ec) {
                do_request_send();
            }
            else {
                do_request_fail();
            }
        });
    }
    void do_request_send() {
        auto self(shared_from_this());
        asio::async_write(socket_, asio::buffer("\x05\x00\x00\01\x00\x00\x00\x00\x00\x00", 10),
            [this, self](const std::error_code& ec, std::size_t size) {
                if (!ec) {
                    do_i_recv();
                    do_o_recv();
                }
            }
        );
    }
    void do_request_fail() {
        // general SOCKS server failure
        asio::async_write(socket_, asio::buffer("\x05\x01\x00\00\x00\x00\x00\x00\x00\x00", 10),
            [](const std::error_code& ec, std::size_t size) {});
    }
    // 成功建立连接，转发数据阶段，出错就结束会话
    void do_i_recv() {
        auto self(shared_from_this());
        socket_.async_read_some(asio::buffer(idata_),
            [this, self](const std::error_code& ec, std::size_t size) {
                if (!ec) {
                    // std::cout << "do_i_recv " << size << std::endl;
                    do_o_send(size);
                }
                else {
                    do_cleanup();
                }
            }
        );
    }
    void do_i_send(std::size_t size) {
        auto self(shared_from_this());
        asio::async_write(socket_, asio::buffer(odata_, size),
            [this, self](const std::error_code& ec, std::size_t size) {
                if (!ec) {
                    do_o_recv();
                }
                else {
                    do_cleanup();
                }
            }
        );
    }
    void do_o_recv() {
        auto self(shared_from_this());
        remote_.async_read_some(asio::buffer(odata_),
            [this, self](const std::error_code& ec, std::size_t size) {
                if (!ec) {
                    // std::cout << "do_o_recv " << size << std::endl;
                    do_i_send(size);
                }
                else {
                    do_cleanup();
                }
            }
        );
    }
    void do_o_send(std::size_t size) {
        auto self(shared_from_this());
        asio::async_write(remote_, asio::buffer(idata_, size),
            [this, self](const std::error_code& ec, std::size_t size) {
                if (!ec) {
                    do_i_recv();
                }
                else {
                    do_cleanup();
                }
            }
        );
    }
    void do_cleanup() {
        socket_.cancel();
        remote_.cancel();
    }

    tcp::socket socket_;
    tcp::socket remote_;
    tcp::resolver resolver_;
    enum {MAX_BUFFER_LENGTH = 65536};
    std::array<unsigned char, MAX_BUFFER_LENGTH> idata_;
    std::array<unsigned char, MAX_BUFFER_LENGTH> odata_;
};

class server
{
public:
    server(asio::io_context& ioc, short port) :
        acceptor_(ioc, tcp::endpoint(tcp::v4(), port)) {
        do_accept();
    }
private:
    void do_accept() {
        acceptor_.async_accept([this](const std::error_code& ec, tcp::socket socket) {
            if (!ec) {
                std::make_shared<session>(std::move(socket))->start();
            }
            do_accept();
        });
    }
    tcp::acceptor acceptor_;
};

int main(int argc, char* argv[])
{
    asio::io_context ioc;

    try {
        server s(ioc, 1234);
        ioc.run();
    }
    catch (...) {
    }

    return 0;
}

