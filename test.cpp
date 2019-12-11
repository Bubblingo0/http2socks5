#include "http2socks5.hpp"

int main(int argc, char* argv[]) {
    try {
        boost::asio::io_context io_context;
        //io_context local_addr local_port socks5_addr socks5_port
        http2socks5::Server srv(io_context, "0.0.0.0", 1082, "10.0.0.128", 1083);
        io_context.run();
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
