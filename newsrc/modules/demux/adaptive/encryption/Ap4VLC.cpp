#include "Ap4.h"
#include "Ap4VLC.h"

#include <vlc_block.h>

typedef struct vlc_frame_t  block_t;

std::vector<unsigned char> AP4_VLC::getKeyID(block_t **pp_block) {

    block_t *p_block = *pp_block;
    
    if(!p_block->i_buffer) {
        return { };
    }

    keyId.clear();

    AP4_MemoryByteStream *stream = new AP4_MemoryByteStream(p_block->p_buffer, p_block->i_buffer);
    AP4_File file = AP4_File(*stream, true);

    stream->Release();

    return keyId;
}

void AP4_VLC::decrypt(block_t **pp_block, const std::vector<unsigned char> &keyId, const std::vector<unsigned char> &key) {

    block_t *p_block = *pp_block;
    
    if(keyId.size() != 32 || key.size() != 32) {
        return;
    }

    unsigned char keyID[16];
    unsigned char decryptionKey[16];
    AP4_ParseHex(reinterpret_cast<const char *>(keyId.data()), keyID, 16);
    AP4_ParseHex(reinterpret_cast<const char *>(key.data()), decryptionKey, 16);

    AP4_ProtectionKeyMap keyMap;
    keyMap.SetKeyForKid(keyID, decryptionKey, 16);

    AP4_MemoryByteStream *input = new AP4_MemoryByteStream(p_block->p_buffer, p_block->i_buffer);
    AP4_MemoryByteStream *output = new AP4_MemoryByteStream();

    AP4_CencDecryptingProcessor processor = AP4_CencDecryptingProcessor(&keyMap);

    if(AP4_FAILED(processor.Process(*input, *output))) {
        input->Release();
        output->Release();
        return;
    }

    p_block = block_Realloc(p_block, 0, output->GetDataSize());
    if(p_block)
        memcpy(p_block->p_buffer, output->GetData(), p_block->i_buffer);

    input->Release();
    output->Release();
}
