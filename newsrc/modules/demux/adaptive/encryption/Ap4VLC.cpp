#include "Ap4.h"
#include "Ap4VLC.h"

std::vector<unsigned char> AP4_VLC::getKeyID(void *inputdata, const size_t inputbytes) {
    
    if(!inputbytes) {
        return { };
    }

    keyId.clear();

    AP4_MemoryByteStream *stream = new AP4_MemoryByteStream(reinterpret_cast<unsigned char *>(inputdata), inputbytes);
    AP4_File file = AP4_File(*stream, true);

    stream->Release();

    return keyId;
}

AP4_MemoryByteStream* AP4_VLC::decrypt(void *inputdata, const size_t inputbytes, const std::vector<unsigned char> &keyId, const std::vector<unsigned char> &key) {
    
    if (keyId.size() != 32 || key.size() != 32) {
        return nullptr;
    }

    unsigned char keyID[16];
    unsigned char decryptionKey[16];
    AP4_ParseHex(reinterpret_cast<const char *>(keyId.data()), keyID, 16);
    AP4_ParseHex(reinterpret_cast<const char *>(key.data()), decryptionKey, 16);

    AP4_ProtectionKeyMap keyMap;
    keyMap.SetKeyForKid(keyID, decryptionKey, 16);

    AP4_MemoryByteStream *input = new AP4_MemoryByteStream(reinterpret_cast<unsigned char *>(inputdata), inputbytes);
    AP4_MemoryByteStream *output = new AP4_MemoryByteStream();

    AP4_CencDecryptingProcessor processor = AP4_CencDecryptingProcessor(&keyMap);

    if (AP4_FAILED(processor.Process(*input, *output))) {
        input->Release();
        output->Release();
        return nullptr;
    }

    input->Release();
    return output;
}
