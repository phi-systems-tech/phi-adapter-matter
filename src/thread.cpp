#include "thread.h"

#include <cerrno>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace phimatter {
namespace {

constexpr int kAnswerTimeoutMs = 2000;

class Console {
public:
    explicit Console(const std::string &path)
    {
        m_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (m_fd < 0) {
            m_error = std::strerror(errno);
            return;
        }
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (path.size() >= sizeof(addr.sun_path)) {
            m_error = "socket path too long";
            close();
            return;
        }
        std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
        if (::connect(m_fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) != 0) {
            m_error = std::strerror(errno);
            close();
        }
    }
    ~Console() { close(); }

    bool ok() const { return m_fd >= 0; }
    const std::string &error() const { return m_error; }

    // Runs one command; the lines before "Done", or false with the error.
    bool run(const std::string &command, std::vector<std::string> &lines)
    {
        lines.clear();
        const std::string request = command + "\n";
        if (::write(m_fd, request.data(), request.size()) != static_cast<ssize_t>(request.size())) {
            m_error = std::strerror(errno);
            return false;
        }
        std::string pending;
        for (;;) {
            pollfd pfd{m_fd, POLLIN, 0};
            const int ready = ::poll(&pfd, 1, kAnswerTimeoutMs);
            if (ready <= 0) {
                m_error = ready == 0 ? "no answer" : std::strerror(errno);
                return false;
            }
            char buffer[512];
            const ssize_t got = ::read(m_fd, buffer, sizeof(buffer));
            if (got <= 0) {
                m_error = got == 0 ? "connection closed" : std::strerror(errno);
                return false;
            }
            pending.append(buffer, static_cast<std::size_t>(got));
            std::size_t eol;
            while ((eol = pending.find('\n')) != std::string::npos) {
                std::string line = pending.substr(0, eol);
                pending.erase(0, eol + 1);
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                if (line == "Done")
                    return true;
                if (line.rfind("Error", 0) == 0) {
                    m_error = line;
                    return false;
                }
                // The daemon echoes the prompt of an interactive session.
                if (line.rfind("> ", 0) == 0)
                    line.erase(0, 2);
                if (!line.empty())
                    lines.push_back(line);
            }
        }
    }

private:
    void close()
    {
        if (m_fd >= 0)
            ::close(m_fd);
        m_fd = -1;
    }

    int m_fd = -1;
    std::string m_error;
};

std::string firstLine(Console &console, const std::string &command)
{
    std::vector<std::string> lines;
    if (!console.run(command, lines) || lines.empty())
        return {};
    return lines.front();
}

} // namespace

std::string ThreadNetwork::summary() const
{
    if (!available)
        return {};
    std::string text = "Thread " + (networkName.empty() ? std::string("network") : networkName);
    if (!state.empty())
        text += ", " + state;
    if (channel > 0)
        text += ", channel " + std::to_string(channel);
    return text;
}

ThreadNetwork queryThreadNetwork(const std::string &socketPath)
{
    ThreadNetwork net;
    Console console(socketPath);
    if (!console.ok()) {
        net.error = console.error();
        return net;
    }
    net.state = firstLine(console, "state");
    if (net.state.empty()) {
        net.error = console.error().empty() ? "no state" : console.error();
        return net;
    }
    net.available = true;
    net.networkName = firstLine(console, "networkname");
    const std::string channel = firstLine(console, "channel");
    net.channel = channel.empty() ? 0 : std::atoi(channel.c_str());
    net.panId = firstLine(console, "panid");
    net.extPanId = firstLine(console, "extpanid");
    net.datasetHex = firstLine(console, "dataset active -x");
    return net;
}

std::vector<std::uint8_t> bytesFromHex(const std::string &hex)
{
    std::vector<std::uint8_t> out;
    if (hex.size() % 2 != 0)
        return out;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return {};
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

} // namespace phimatter
