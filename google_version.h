#ifndef GOOGLE_VERSION_H_
#define GOOGLE_VERSION_H_

#include <map>
#include <string>

class VersionReader
{
  public:
    virtual ~VersionReader()
    {
    }
    virtual bool ReadVersion(int* major, int* minor, int* point,
                             int* subpoint) = 0;
    virtual std::string ReadVersion() = 0;
    virtual std::string ReadDistro() = 0;
};

// Abstracts access to the release file as key-value pairs, to allow mocking.
class ReleaseReader
{
  public:
    virtual ~ReleaseReader()
    {
    }
    virtual std::map<std::string, std::string> ReadReleaseFile() = 0;
};

class GoogleVersionReader : public VersionReader
{
  public:
    explicit GoogleVersionReader(ReleaseReader* release_reader);
    bool ReadVersion(int* major, int* minor, int* point,
                     int* subpoint) override;
    std::string ReadVersion() override;
    std::string ReadDistro() override;

  private:
    const std::map<std::string, std::string> os_release_items_;

    std::string GetOsReleaseValue(const std::string& key) const;
};

// Reader capable of parsing the format used in /etc/os-release.
class OsReleaseReader : public ReleaseReader
{
  public:
    // If no os_release_path is provided, default to the system file.
    explicit OsReleaseReader(
        const std::string& os_release_path = kOsReleaseDefaultPath);
    std::map<std::string, std::string> ReadReleaseFile() override;

    static std::string FindReleasePath(const std::string& override_path);

  private:
    static const char* const kOsReleaseDefaultPath;

    const std::string os_release_path_;
};

#endif // GOOGLE_VERSION_H_
