#ifndef _AP4_VLC_H_
#define _AP4_VLC_H_

#include <string>
#include <vector>

typedef struct vlc_frame_t block_t;

class AP4_VLC final {
private:
    friend class AP4_AesBlockCipher;
    friend class AP4_CencTrackEncryption;
    AP4_VLC() = delete;
    AP4_VLC(const AP4_VLC& other) = delete;
    AP4_VLC& operator=(const AP4_VLC& other) = delete;
    AP4_VLC(AP4_VLC&& other) = delete;
    AP4_VLC& operator=(AP4_VLC&& other) = delete;

public:
    static std::vector<unsigned char> getKeyID(block_t **);
    static void decrypt(block_t **, const std::vector<unsigned char> &, const std::vector<unsigned char> &);

private:
    inline static std::string keyId = std::string("");
};

#endif // !_AP4_VLC_H_
