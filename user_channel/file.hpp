#pragma once

#include <stdio.h>
#include <sys/inotify.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <phosphor-logging/lg2.hpp>

#include <array>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>

namespace phosphor
{
namespace user
{

namespace fs = std::filesystem;

/** @class File
 *  @brief Responsible for handling file pointer
 *  Needed by putspent(3)
 */
class File
{
  private:
    /** @brief handler for operating on file */
    FILE* fp = nullptr;

    /** @brief File name. Needed in the case where the temp
     *         needs to be removed
     */
    const std::string& name;

    /** @brief Should the file be removed at exit */
    bool removeOnExit = false;

  public:
    File() = delete;
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    File(File&&) = delete;
    File& operator=(File&&) = delete;

    /** @brief Opens file and uses it to do file operation
     *
     *  @param[in] name         - File name
     *  @param[in] mode         - File open mode
     *  @param[in] removeOnExit - File to be removed at exit or no
     */
    File(const std::string& name, const std::string& mode,
         bool removeOnExit = false) : name(name), removeOnExit(removeOnExit)
    {
        fp = fopen(name.c_str(), mode.c_str());
    }

    /** @brief Opens file using provided file descriptor
     *
     *  @param[in] fd           - File descriptor
     *  @param[in] name         - File name
     *  @param[in] mode         - File open mode
     *  @param[in] removeOnExit - File to be removed at exit or no
     */
    File(int fd, const std::string& name, const std::string& mode,
         bool removeOnExit = false) : name(name), removeOnExit(removeOnExit)
    {
        fp = fdopen(fd, mode.c_str());
    }

    ~File()
    {
        if (fp)
        {
            fclose(fp);
        }

        // Needed for exception safety
        if (removeOnExit && fs::exists(name))
        {
            fs::remove(name);
        }
    }

    auto operator()()
    {
        return fp;
    }
};

class FileWatch
{
  public:
    FileWatch(const FileWatch&) = delete;
    FileWatch& operator=(const FileWatch&) = delete;
    FileWatch(FileWatch&&) = delete;
    FileWatch& operator=(FileWatch&&) = delete;

    FileWatch(boost::asio::io_context& io, const std::string& path,
              std::function<void()>&& cb) :
        inotifyConn(io), watchPath(path), callback(std::move(cb))
    {
        registerInotify();
    }

    ~FileWatch()
    {
        inotify_rm_watch(inotifyConn.native_handle(), IN_ALL_EVENTS);
    }

  private:
    void registerInotify()
    {
        int fd = inotify_init1(IN_NONBLOCK);
        if (fd < 0)
        {
            lg2::error("Failed to initialize inotify");
            return;
        }

        inotifyConn.assign(fd);

        auto parentPath = std::filesystem::path(watchPath).parent_path();

        int wdDir =
            inotify_add_watch(inotifyConn.native_handle(), parentPath.c_str(),
                              IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVE);
        if (wdDir < 0)
        {
            lg2::error("Failed to add watch for inotify");
            return;
        }

        startInotify();
    }

    void onInotify(const boost::system::error_code& ec, std::size_t length)
    {
        if (ec)
        {
            lg2::error("Failed to read inotify");
            return;
        }

        struct inotify_event* event = nullptr;
        for (char* ptr = readBuffer.data(); ptr < readBuffer.data() + length;
             ptr += sizeof(struct inotify_event) + event->len)
        {
            event = reinterpret_cast<struct inotify_event*>(ptr);
            if (event->mask & IN_CREATE)
            {
                lg2::debug("File {FILE} created", "FILE", event->name);
            }
            else if (event->mask & IN_DELETE)
            {
                lg2::debug("File {FILE} deleted", "FILE", event->name);
            }
            else if (event->mask & IN_MOVE)
            {
                lg2::debug("File {FILE} moved", "FILE", event->name);
            }

            if (std::string(event->name) ==
                std::filesystem::path(watchPath).filename().string())
            {
                lg2::info("File {FILE} changed", "FILE", event->name);
                callback();
            }
        }

        startInotify();
    }

    void startInotify()
    {
        inotifyConn.async_read_some(
            boost::asio::buffer(readBuffer),
            std::bind_front(&FileWatch::onInotify, this));
    }

    boost::asio::posix::stream_descriptor inotifyConn;
    std::string watchPath;
    std::function<void()> callback;
    std::array<char, 1024> readBuffer{};
};

} // namespace user
} // namespace phosphor
