#ifndef VLC_AP4_H
#define VLC_AP4_H

#include <mutex>
#include <string>
#include <vector>

class VLC_AP4 final {
private:
    friend class AP4_CencTrackEncryption;
    VLC_AP4() = delete;
    ~VLC_AP4() = delete;
    VLC_AP4(const VLC_AP4& other) = delete;
    VLC_AP4& operator=(const VLC_AP4& other) = delete;
    VLC_AP4(VLC_AP4&& other) = delete;
    VLC_AP4& operator=(VLC_AP4&& other) = delete;

    void* operator new(size_t);
    void* operator new(size_t, void*);
    void* operator new[](size_t);
    void* operator new[](size_t, void*);

public:
    static std::string getKeyID(void *, const size_t);
    static void decrypt(void *inputdata, const size_t inputbytes, const std::string &keyId, const std::vector<unsigned char> &key, void *originaldata, const size_t originalbytes);
    static void modifyInit(void *, const size_t);

private:
    inline static std::string keyId;
    inline static std::mutex m_mutex;
};

#endif // !VLC_AP4_H
