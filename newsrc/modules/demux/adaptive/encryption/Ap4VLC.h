#ifndef _AP4_VLC_H_
#define _AP4_VLC_H_

#include <string>
#include <vector>

typedef struct vlc_frame_t block_t;

class AP4_VLC final {
private:
    friend class AP4_CencTrackEncryption;
    AP4_VLC() = delete;
    AP4_VLC(const AP4_VLC& other) = delete;
    AP4_VLC& operator=(const AP4_VLC& other) = delete;
    AP4_VLC(AP4_VLC&& other) = delete;
    AP4_VLC& operator=(AP4_VLC&& other) = delete;

public:
    static std::string getKeyID(block_t **);
    static void decrypt(block_t **pp_block, const std::string &keyId, const std::vector<unsigned char> &key);

private:
    inline static std::string keyId;
};

#endif // !_AP4_VLC_H_
