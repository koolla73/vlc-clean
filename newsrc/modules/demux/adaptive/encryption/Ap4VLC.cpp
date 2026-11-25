#include "Ap4.h"
#include "Ap4VLC.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>

#ifdef __APPLE__ 
#include <arpa/inet.h>
#else
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#define ntohll(x)   ((((std::uint64_t)ntohl(x&0xFFFFFFFF)) << 32) + ntohl(x >> 32))
#endif

#define uint32be(header) (ntohl(*reinterpret_cast<std::uint32_t *>(header)))
#define uint64be(header) (ntohll(*reinterpret_cast<std::uint64_t *>(header)))


namespace {
    std::uint32_t uint32E(std::array<std::uint8_t, 4>* header)
    {
        return uint32be(header);
    }

    std::uint64_t uint64E(std::array<std::uint8_t, 4>* header)
    {
        return uint64be(header);
    }

    std::uint32_t uint32E(std::array<std::uint8_t, 8>* header)
    {
        return uint32be(header);
    }

    std::uint64_t uint64E(std::array<std::uint8_t, 8>* header)
    {
        return uint64be(header);
    }

    void findBox(std::uint8_t *inputdata, const size_t inputbytes, const std::array<std::uint8_t, 4> &boxToFind, std::uint64_t &boxPos, bool &isExtendedSize, const std::uint64_t startBytePos = 0)
    {
        std::uint64_t currentBytePosition = startBytePos;
        std::array<std::uint8_t, 4> header = { 0 };
        std::uint32_t payloadSize = 0;
        std::uint64_t payloadSize64 = 0;

        while(currentBytePosition < inputbytes)
        {
            isExtendedSize = false;
            std::copy_n(inputdata + currentBytePosition, 4, std::begin(header));
            payloadSize = payloadSize64 = uint32E(&header);
            if(payloadSize == 0)
            {
                // Box size is whole file.
                payloadSize64 = inputbytes;
            }
            else if(payloadSize == 1)
            {
                // Box size is 64-bit.
                isExtendedSize = true;
                std::array<unsigned char, 8> header64 = { 0 };
                std::copy_n(inputdata + currentBytePosition + 4 + 4, 8, std::begin(header64));
                payloadSize64 = uint64E(&header64);
            }

            header.fill(0);
            std::copy_n(inputdata + currentBytePosition + 4, 4, std::begin(header));

            if(header == boxToFind)
            {
                boxPos = currentBytePosition;
                return;
            }

            header.fill(0);

            currentBytePosition += payloadSize64;
        }
    }
}

std::string VLC_AP4::getKeyID(void *inputdata, const size_t inputbytes)
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    if(!inputbytes)
        return { };

    keyId.clear();

    AP4_MemoryByteStream *stream = new AP4_MemoryByteStream(reinterpret_cast<unsigned char *>(inputdata), inputbytes);
    AP4_File file = AP4_File(*stream, true);

    stream->Release();

    return keyId;
}

void VLC_AP4::decrypt(void *inputdata, const size_t inputbytes, const std::string &keyId, const std::vector<unsigned char> &key)
{
    if (keyId.size() != 32 || key.size() != 32)
        return;

    std::uint8_t keyID[16];
    std::uint8_t decryptionKey[16];
    AP4_ParseHex(keyId.c_str(), keyID, 16);
    AP4_ParseHex(reinterpret_cast<const char *>(key.data()), decryptionKey, 16);

    AP4_ProtectionKeyMap keyMap;
    keyMap.SetKeyForKid(keyID, decryptionKey, 16);

    AP4_MemoryByteStream *input = new AP4_MemoryByteStream(reinterpret_cast<std::uint8_t *>(inputdata), inputbytes);
    AP4_MemoryByteStream *output = new AP4_MemoryByteStream();

    AP4_CencDecryptingProcessor processor = AP4_CencDecryptingProcessor(&keyMap);

    if(AP4_FAILED(processor.Process(*input, *output)) || !output->GetDataSize())
    {
        input->Release();
        output->Release();
        return;
    }

    input->Release();

    std::uint64_t encryptedMdatBytePosition = 0;
    std::uint64_t encryptedMdatBoxSize = 0;
    std::uint64_t decryptedMdatBytePosition = 0;
    std::uint64_t decryptedMdatBoxSize = 0;
    findBox(reinterpret_cast<std::uint8_t *>(inputdata), inputbytes, { 'm', 'd', 'a', 't' }, encryptedMdatBytePosition, encryptedMdatBoxSize);
    findBox(const_cast<std::uint8_t *>(output->GetData()), output->GetDataSize(), { 'm', 'd', 'a', 't' }, decryptedMdatBytePosition, decryptedMdatBoxSize);

    if(!decryptedMdatBoxSize || encryptedMdatBoxSize != decryptedMdatBoxSize)
    {
        output->Release();
        return;
    }

    memcpy(inputdata + encryptedMdatBytePosition, output->GetData() + decryptedMdatBytePosition, decryptedMdatBoxSize);

    output->Release();
}

AP4_MemoryByteStream *VLC_AP4::modifyInit(void *inputdata, const size_t inputbytes)
{
    if(!inputbytes)
        return nullptr;

    AP4_MemoryByteStream *input = new AP4_MemoryByteStream(reinterpret_cast<unsigned char *>(inputdata), inputbytes);

    AP4_AtomFactory &atom_factory = AP4_DefaultAtomFactory::Instance_;
    std::unique_ptr<AP4_MoovAtom> moov;
    AP4_UI64 stream_offset = 0;

    for(AP4_Atom *atom = nullptr; AP4_SUCCEEDED(atom_factory.CreateAtomFromStream(*input, atom)); input->Tell(stream_offset))
    {
        if(atom->GetType() == AP4_ATOM_TYPE_MOOV)
            moov = std::unique_ptr<AP4_MoovAtom>(AP4_DYNAMIC_CAST(AP4_MoovAtom, atom));
    }

    if(!moov)
    {
        input->Release();
        return nullptr;
    }

    AP4_List<AP4_TrakAtom> *trak_atoms = &moov.get()->GetTrakAtoms();
    if(!trak_atoms->ItemCount())
    {
        input->Release();
        return nullptr;
    }

    AP4_StsdAtom *stsd = AP4_DYNAMIC_CAST(AP4_StsdAtom, trak_atoms->FirstItem()->GetData()->FindChild("mdia/minf/stbl/stsd"));
    if(stsd == nullptr)
    {
        input->Release();
        return nullptr;
    }

    AP4_Array<AP4_ProtectedSampleDescription*> sample_descs;
    AP4_Array<AP4_SampleEntry*> sample_entries;

    for(std::uint32_t i = 0; i < stsd->GetSampleDescriptionCount(); i++)
    {
        AP4_SampleDescription* sample_desc = stsd->GetSampleDescription(i);
        AP4_SampleEntry* sample_entry = stsd->GetSampleEntry(i);
        if (sample_desc == NULL || sample_entry == NULL)
            continue;

        if(sample_desc->GetType() == AP4_SampleDescription::TYPE_PROTECTED)
        {
            AP4_ProtectedSampleDescription* protected_desc =
                static_cast<AP4_ProtectedSampleDescription*>(sample_desc);
            if(protected_desc->GetSchemeType() == AP4_PROTECTION_SCHEME_TYPE_PIFF ||
                protected_desc->GetSchemeType() == AP4_PROTECTION_SCHEME_TYPE_CENC ||
                protected_desc->GetSchemeType() == AP4_PROTECTION_SCHEME_TYPE_CBC1 ||
                protected_desc->GetSchemeType() == AP4_PROTECTION_SCHEME_TYPE_CENS ||
                protected_desc->GetSchemeType() == AP4_PROTECTION_SCHEME_TYPE_CBCS)
            {
                sample_descs.Append(protected_desc);
                sample_entries.Append(sample_entry);
            }
        }
    }

    if(sample_entries.ItemCount() == 0 || sample_descs.ItemCount() == 0)
    {
        input->Release();
        return nullptr;
    }

    AP4_String sampleEntryCodeString;
    const AP4_Result result = sample_descs[0]->GetCodecString(sampleEntryCodeString);
    if(AP4_FAILED(result))
    {
        input->Release();
        return nullptr;
    }

    const std::string sampleEntryCode(sampleEntryCodeString.GetChars(), sampleEntryCodeString.GetLength());
    if(sampleEntryCode.size() != 4)
    {
        input->Release();
        return nullptr;
    }

    const std::uint32_t format = sample_descs[0]->GetOriginalFormat();

    std::uint64_t moovPos, trakPos, mdiaPos, minfPos, stblPos, stsdPos, encxPos = 0;
    bool moov64, trak64, mdia64, minf64, stbl64, stsd64, encx64 = false;
    findBox(const_cast<std::uint8_t *>(input->GetData()), input->GetDataSize(), { 'm', 'o', 'o', 'v' }, moovPos, moov64);
    findBox(const_cast<std::uint8_t *>(input->GetData()), input->GetDataSize(), { 't', 'r', 'a', 'k' }, trakPos, trak64, moovPos + 4 + 4 + ((moov64 == true) ? 8 : 0));
    findBox(const_cast<std::uint8_t *>(input->GetData()), input->GetDataSize(), { 'm', 'd', 'i', 'a' }, mdiaPos, mdia64, trakPos + 4 + 4 + ((trak64 == true) ? 8 : 0));
    findBox(const_cast<std::uint8_t *>(input->GetData()), input->GetDataSize(), { 'm', 'i', 'n', 'f' }, minfPos, minf64, mdiaPos + 4 + 4 + ((mdia64 == true) ? 8 : 0));
    findBox(const_cast<std::uint8_t *>(input->GetData()), input->GetDataSize(), { 's', 't', 'b', 'l' }, stblPos, stbl64, minfPos + 4 + 4 + ((minf64 == true) ? 8 : 0));
    findBox(const_cast<std::uint8_t *>(input->GetData()), input->GetDataSize(), { 's', 't', 's', 'd' }, stsdPos, stsd64, stblPos + 4 + 4 + ((stbl64 == true) ? 8 : 0));
    findBox(
        const_cast<std::uint8_t *>(input->GetData()), input->GetDataSize(),
        { static_cast<std::uint8_t>(sampleEntryCode[0]), static_cast<std::uint8_t>(sampleEntryCode[1]), static_cast<std::uint8_t>(sampleEntryCode[2]), static_cast<std::uint8_t>(sampleEntryCode[3]) },
        encxPos, encx64, stsdPos + 4 + 4 + 4 + 4 + ((stsd64 == true) ? 8 : 0)
    );

    std::uint8_t fourcc[4];
    fourcc[0] = static_cast<uint8_t>(format >> 24);
    fourcc[1] = static_cast<uint8_t>(format >> 16);
    fourcc[2] = static_cast<uint8_t>(format >> 8);
    fourcc[3] = static_cast<uint8_t>(format);

    std::copy_n(&fourcc[0], 1, const_cast<std::uint8_t *>(input->GetData()) + encxPos + 4);
    std::copy_n(&fourcc[1], 1, const_cast<std::uint8_t *>(input->GetData()) + encxPos + 5);
    std::copy_n(&fourcc[2], 1, const_cast<std::uint8_t *>(input->GetData()) + encxPos + 6);
    std::copy_n(&fourcc[3], 1, const_cast<std::uint8_t *>(input->GetData()) + encxPos + 7);

    return input;
}
