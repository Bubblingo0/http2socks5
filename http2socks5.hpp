
#ifndef HTTP_SOCKS5_FORWARDER_HPP
#define HTTP_SOCKS5_FORWARDER_HPP

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/http.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <iostream>

namespace http2socks5
{
using namespace boost::asio::ip;

class Session : public boost::enable_shared_from_this<Session>
{
public:
    Session(boost::asio::io_context &io_context, const std::string &socks5_host,
            unsigned short socks5_port)
        : io_context_(io_context), resolver_(io_context),
          client_socket_(io_context), server_socket_(io_context),
          socks5_host_(socks5_host), socks5_port_(socks5_port) {}

    tcp::socket &client_socket() { return client_socket_; }

    void start()
    {
        type = NONE;
        status = SOCKS5_NEGOTIATION;
        client_async_read();
    }

private:
    enum Type
    {
        NONE,
        SOCKS5,
        HTTP,
        HTTPS
    } type;

    enum Status
    {
        SOCKS5_NEGOTIATION,
        SOCKS5_FORWARD
    } status;

    void close()
    {
        if (client_socket_.is_open())
            client_socket_.close();

        if (server_socket_.is_open())
            server_socket_.close();
    }

    void client_async_read()
    {
        const auto self = shared_from_this();
        client_socket_.async_read_some(
            boost::asio::buffer(client_data_, max_length),
            [this, self](const boost::system::error_code error, size_t len) {
                if (error)
                {
                    close();
                    return;
                }
                client_data_len_ = len;
                on_client_recv();
            });
    }

    void server_async_read()
    {
        const auto self = shared_from_this();
        server_socket_.async_read_some(
            boost::asio::buffer(server_data_, max_length),
            [this, self](const boost::system::error_code error, size_t len) {
                if (error)
                {
                    close();
                    return;
                }

                server_data_len_ = len;
                on_server_recv();
            });
    }

    void server_async_write()
    {
        const auto self = shared_from_this();
        if (SOCKS5_NEGOTIATION == status)
        {
            boost::asio::async_write(
                server_socket_, boost::asio::buffer(negotiate_msg_),
                [this, self](const boost::system::error_code error, size_t len) {
                    if (error)
                    {
                        close();
                        return;
                    }
                    on_server_writed();
                });
        }
        else
        {
            boost::asio::async_write(
                server_socket_, boost::asio::buffer(client_data_, client_data_len_),
                [this, self](const boost::system::error_code error, size_t len) {
                    if (error)
                    {
                        close();
                        return;
                    }
                    on_server_writed();
                });
        }
    }

    void client_async_write()
    {
        const auto self = shared_from_this();
        if (HTTPS == type && SOCKS5_NEGOTIATION == status)
        {
            // write HTTP 200 (Connection Established) response
            // ref:https://wiki.squid-cache.org/Features/HTTPS#CONNECT_tunnel
            static const char data[] = "HTTP/1.1 200 Connection established\r\n\r\n";
            boost::asio::async_write(
                client_socket_, boost::asio::buffer(data, strlen(data)),
                [this, self](const boost::system::error_code error, size_t len) {
                    if (error)
                    {
                        close();
                        return;
                    }
                    on_client_writed();
                });
        }
        else
        {
            boost::asio::async_write(
                client_socket_, boost::asio::buffer(server_data_, server_data_len_),
                [this, self](const boost::system::error_code error, size_t len) {
                    if (error)
                    {
                        close();
                        return;
                    }
                    on_client_writed();
                });
        }
    }

    void on_client_recv()
    {
        if (client_data_len_ < 2)
        {
            close();
            return;
        }

        if (SOCKS5_NEGOTIATION == status)
        {
            if (client_data_[0] == '\x05' && client_data_[1] == '\x01')
            {
                // forward directly on socks5
                type = SOCKS5;
                status = SOCKS5_FORWARD;
                socks5_connect();
                return;
            }

            if (client_data_[0] == 'C' && client_data_[1] == 'O' &&
                client_data_[2] == 'N' && client_data_[3] == 'N' &&
                client_data_[4] == 'E' && client_data_[5] == 'C' &&
                client_data_[6] == 'T')
            {
                type = HTTPS;
            }
            else
            {
                type = HTTP;
            }

            process_client_header();
            socks5_connect();
        }
        else if (SOCKS5_FORWARD == status)
        {
            if (HTTP == type)
            {
                process_client_header();
            }
            server_async_write();
        }
    }

    void on_server_recv()
    {
        if (SOCKS5_NEGOTIATION == status)
        {
            std::string data(server_data_, server_data_len_);
            if (server_data_len_ == 2 && server_data_[0] == '\x05' &&
                server_data_[1] == '\x00')
            {
                // ref:https://github.com/unisx/privoxy/blob/b771dc0f85e71c816287160590c8ddd7f0d52ae4/gateway.c#L933
                char buf[300];
                size_t client_pos = 0;
                size_t host_len = remote_server_host_.length();
                buf[client_pos++] = '\x05'; /* Version */
                buf[client_pos++] = '\x01'; /* TCP connect */
                buf[client_pos++] = '\x00'; /* Reserved, must be 0x00 */
                buf[client_pos++] = '\x03'; /* Address is domain name */
                buf[client_pos++] = (char)(host_len & 0xffu);
                assert(sizeof(buf) - client_pos > (size_t)255);
                /* Using strncpy because we really want the nul byte padding. */
                strncpy(buf + client_pos, remote_server_host_.c_str(),
                        sizeof(buf) - client_pos);
                client_pos += (host_len & 0xffu);
                buf[client_pos++] = (char)((remote_server_port_ >> 8) & 0xff);
                buf[client_pos++] = (char)((remote_server_port_)&0xff);

                negotiate_msg_ = std::move(std::string(buf, client_pos));
                server_async_write();
            }
            else if (server_data_len_ == 10 && server_data_[0] == '\x05' &&
                     server_data_[1] == '\x00')
            {
                // socks5 negotiation finished
                if (HTTPS == type)
                {
                    client_async_write();
                }
                else
                {
                    status = SOCKS5_FORWARD;
                    server_async_write();
                    server_async_read();
                }
            }
            else
            {
                close();
            }
        }
        else
        {
            client_async_write();
        }
    }

    void on_server_writed()
    {
        if (SOCKS5_NEGOTIATION == status)
        {
            server_async_read();
        }
        else
        {
            client_async_read();
        }
    }

    void on_client_writed()
    {
        if (SOCKS5_NEGOTIATION == status)
        {
            status = SOCKS5_FORWARD;
            server_async_read();
            client_async_read();
        }
        else
        {
            server_async_read();
        }
    }

    void process_client_header()
    {
        std::string header(client_data_, client_data_len_);

        boost::system::error_code ec;
        using namespace boost::beast;
        boost::beast::http::request_parser<boost::beast::http::string_body> p;
        p.put(boost::asio::buffer(header), ec);

        const std::string uri = p.get().target().to_string();
        const std::string host = p.get()[http::field::host].to_string();
        const std::string path = uri.substr(uri.find(host) + host.length());

        std::string port;
        std::string server;

        size_t pos = host.find(':');
        if (pos != std::string::npos)
        {
            remote_server_host_ = host.substr(0, pos);
            port = host.substr(pos + 1);
        }
        else
        {
            remote_server_host_ = host;
        }

        if (port.empty())
        {
            remote_server_port_ = type == HTTPS ? 443 : 80;
        }
        else
        {
            remote_server_port_ = std::stoi(port);
        }

        if (HTTPS == type)
        {
            return;
        }

        // replace full url with path
        pos = header.find_first_of(' ');
        header.replace(pos + 1, uri.length(), path);

        pos = header.find("Proxy-Connection");
        if (pos != std::string::npos)
        {
            header.replace(pos, 16, "Connection");
        }

        // modify client's header
        client_data_len_ = header.length();
        memcpy(client_data_, header.c_str(), client_data_len_);
    }

    void socks5_connect()
    {
        tcp::resolver::query query(socks5_host_, std::to_string(socks5_port_));
        auto self = shared_from_this();

        resolver_.async_resolve(query, [this, self](
                                           const boost::system::error_code &error,
                                           tcp::resolver::results_type results) {
            if (error)
            {
                close();
                return;
            }
            const auto endpoint_iter = results.begin();
            server_socket_.async_connect(
                *endpoint_iter, [this, self](const boost::system::error_code error) {
                    if (error)
                    {
                        close();
                        return;
                    }
                    on_socks5_connected();
                });
        });
    }

    void on_socks5_connected()
    {
        if (SOCKS5_NEGOTIATION == status)
        {
            char buf[300];
            size_t client_pos = 0;
            buf[client_pos++] = '\x05'; /* Version */
            buf[client_pos++] = '\x01'; /* One authentication method supported */
            buf[client_pos++] = '\x00'; /* The no authentication authentication method */

            // start socks5 NEGOTIATION
            negotiate_msg_ = std::move(std::string(buf, client_pos));
            server_async_write();
        }
        else
        {
            // SOCKS5_FORWARD
            server_async_write();
            server_async_read();
        }
    }

    boost::asio::io_context &io_context_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ip::tcp::socket client_socket_;
    boost::asio::ip::tcp::socket server_socket_;

    std::string socks5_host_;
    unsigned short socks5_port_;
    
    int client_data_len_;
    int server_data_len_;

    enum
    {
        max_length = 8192
    }; // 8KB

    char client_data_[max_length];
    char server_data_[max_length];

    std::string negotiate_msg_;

    std::string remote_server_host_;
    unsigned short remote_server_port_;
};

class Server
{
public:
    Server(boost::asio::io_context &io_context, const std::string &local_host,
           unsigned short local_port, const std::string &socks5_host,
           unsigned short socks5_port)
        : io_context_(io_context), acceptor_(io_context),
          socks5_host_(socks5_host), socks5_port_(socks5_port)
    {
        tcp::resolver resolver(io_context_);
        tcp::endpoint endpoint =
            *resolver.resolve(local_host, std::to_string(local_port)).begin();
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(tcp::acceptor::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen();
        std::cout << endpoint.address().to_string() << ":" << endpoint.port()
                  << std::endl;
        do_accept();
    }

protected:
    void do_accept()
    {
        auto session = boost::shared_ptr<Session>(
            new Session(io_context_, socks5_host_, socks5_port_));
        acceptor_.async_accept(
            session->client_socket(),
            [this, session](const boost::system::error_code error) {
                if (!error)
                {
                    session->start();
                }
                do_accept();
            });
    }

private:
    boost::asio::io_context &io_context_;
    tcp::acceptor acceptor_;
    std::string socks5_host_;
    unsigned short socks5_port_; 
};
} // namespace http2socks5
#endif // HTTP_SOCKS5_FORWARDER_HPP
