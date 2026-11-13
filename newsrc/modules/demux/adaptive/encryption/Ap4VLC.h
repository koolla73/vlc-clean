#ifndef _AP4_VLC_H_
#define _AP4_VLC_H_

#include <mutex>
#include <string>
#include <vector>

class AP4_MemoryByteStream;

class AP4_VLC final {
private:
    friend class AP4_CencTrackEncryption;
    AP4_VLC() = delete;
    AP4_VLC(const AP4_VLC& other) = delete;
    AP4_VLC& operator=(const AP4_VLC& other) = delete;
    AP4_VLC(AP4_VLC&& other) = delete;
    AP4_VLC& operator=(AP4_VLC&& other) = delete;

public:
    static std::string getKeyID(void *inputdata, const size_t inputbytes);
    static AP4_MemoryByteStream* decrypt(void *inputdata, const size_t inputbytes, const std::string &keyId, const std::vector<unsigned char> &key);

private:
    inline static std::string keyId;
    inline static std::mutex mutex;
};

#endif // !_AP4_VLC_H_
