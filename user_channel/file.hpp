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

/** @class FileWatch
 *  @brief Watches for file or directory changes
 *
 * @param[in] io - boost asio io context
 * @param[in] isDir - Is the path a directory
 * @param[in] path - Path to watch, if isDir is true, this is the directory,
 * else watch the parent directory
 * @param[in] cb - Callback to be called on file change
 * the first argument is the inotify event mask, the second is the full path
 */
class FileWatch
{
  public:
    FileWatch(const FileWatch&) = delete;
    FileWatch& operator=(const FileWatch&) = delete;
    FileWatch(FileWatch&&) = delete;
    FileWatch& operator=(FileWatch&&) = delete;

    FileWatch(boost::asio::io_context& io, bool isDir, const std::string& path,
              std::function<void(uint32_t, const std::string&)> cb) :
        inotifyConn(io), isDir(isDir), watchPath(path), callback(std::move(cb))
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

        target = isDir ? watchPath : fs::path(watchPath).parent_path().string();

        int wdDir =
            inotify_add_watch(inotifyConn.native_handle(), target.c_str(),
                              IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVE);
        if (wdDir < 0)
        {
            lg2::error("Failed to add watch for inotify on {PATH}, ERR: {ERR}",
                       "PATH", target, "ERR", strerror(errno));
            return;
        }

        startInotify();
    }

    void onInotify(const boost::system::error_code& ec, std::size_t length)
    {
        if (ec)
        {
            lg2::error("Failed to read inotify event: {ERR}", "ERR",
                       ec.message());
            return;
        }

        struct inotify_event* event = nullptr;
        for (char* ptr = readBuffer.data(); ptr < readBuffer.data() + length;
             ptr += sizeof(struct inotify_event) + event->len)
        {
            event = reinterpret_cast<struct inotify_event*>(ptr);
            std::string full = std::filesystem::path(target) / event->name;
            callback(event->mask, full);
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
    bool isDir = false;
    std::string watchPath;
    std::function<void(uint32_t, const std::string&)> callback;
    std::array<char, 1024> readBuffer{};
    std::string target;
};

} // namespace user
} // namespace phosphor
