/*
 * SegmentChunk.cpp
 *****************************************************************************
 * Copyright (C) 2014 - 2015 VideoLAN Authors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "SegmentChunk.hpp"
#include "Segment.h"
#include "BaseRepresentation.h"
#include "../encryption/CommonEncryption.hpp"
#include "../encryption/Ap4ByteStream.h"

#include <vlc_block.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>

using namespace adaptive::playlist;
using namespace adaptive::encryption;
using namespace adaptive;

namespace
{
    static constexpr const std::array<unsigned char, 4> mdatBox{ 'm', 'd', 'a', 't' };

    std::uint32_t uint32E(std::array<unsigned char, 4>* header) {
        return uint32be(header);
    }

    std::uint64_t uint64E(std::array<unsigned char, 4>* header) {
        return uint64be(header);
    }

    std::uint32_t uint32E(std::array<unsigned char, 8>* header) {
        return uint32be(header);
    }

    std::uint64_t uint64E(std::array<unsigned char, 8>* header) {
        return uint64be(header);
    }

    void findBox(void *block, const std::uint64_t block_size, const std::array<unsigned char, 4> &box, std::uint64_t &boxPos, std::uint64_t &boxSize)
    {

        std::uint64_t currentBytePosition = 0;
        std::array<unsigned char, 4> header = { 0 };
        std::uint32_t payloadSize = 0;
        std::uint64_t payloadSize64 = 0;

        while (currentBytePosition < block_size)
        {
            std::copy_n(reinterpret_cast<unsigned char*>(block) + currentBytePosition, 4, std::begin(header));
            payloadSize = payloadSize64 = uint32E(&header);
            if (payloadSize == 0)
            {
                // Box size is whole file.
                payloadSize64 = block_size;
            }
            else if (payloadSize == 1)
            {
                // Box size is 64-bit.
                std::array<unsigned char, 8> header64 = { 0 };
                std::copy_n(reinterpret_cast<unsigned char*>(block) + currentBytePosition + 4 + 4, 8, std::begin(header64));
                payloadSize64 = uint64E(&header64);
            }

            header.fill(0);
            std::copy_n(reinterpret_cast<unsigned char*>(block) + currentBytePosition + 4, 4, std::begin(header));

            if (header == box)
            {
                boxPos = currentBytePosition;
                boxSize = payloadSize64;
            }

            header.fill(0);
            currentBytePosition += payloadSize64;
        }
    }

    void copyMdat(AP4_MemoryByteStream *decryptedData, block_t *p_block)
    {
        std::array<unsigned char, 4> header = { 0 };
        std::uint32_t payloadSize = 0;
        std::uint64_t payloadSize64 = 0;
        std::uint64_t currentBytePosition = 0;
        std::uint64_t encryptedMdatBytePosition = 0;
        std::uint64_t encryptedMdatBoxSize = 0;
        std::uint64_t decryptedMdatBytePosition = 0;
        std::uint64_t decryptedMdatBoxSize = 0;

        findBox(p_block->p_buffer, p_block->i_buffer, mdatBox, encryptedMdatBytePosition, encryptedMdatBoxSize);
        findBox(const_cast<unsigned char*>(decryptedData->GetData()), decryptedData->GetDataSize(), mdatBox, decryptedMdatBytePosition, decryptedMdatBoxSize);

        memcpy(p_block->p_buffer + encryptedMdatBytePosition, decryptedData->GetData() + decryptedMdatBytePosition, decryptedMdatBoxSize);
    }
}

SegmentChunk::SegmentChunk(AbstractChunkSource *source, BaseRepresentation *rep_) :
    AbstractChunk(source)
{
    rep = rep_;
    encryptionSession = nullptr;
    discontinuity = false;
    discontinuitySequenceNumber = 0;
}

SegmentChunk::~SegmentChunk()
{
    delete encryptionSession;
}

bool SegmentChunk::decrypt(block_t **pp_block)
{
    block_t *p_block = *pp_block;

    const bool b_last = !hasMoreData();
    p_block->i_buffer = encryptionSession->decrypt(p_block->p_buffer,
                                                   p_block->i_buffer, b_last);
    if(b_last)
        encryptionSession->close();

    return true;
}

void SegmentChunk::onDownload(block_t **pp_block)
{
    block_t *p_block = *pp_block;
    
    if(encryptionSession && encryptionSession->getMethod() == CommonEncryption::Method::AES_128)
    {
        decrypt(pp_block);
    }
    else if(encryptionSession && encryptionSession->getMethod() == CommonEncryption::Method::AES_Ctr && source->getChunkType() == adaptive::http::ChunkType::Init)
    {
        rep->saveInitData(pp_block);
        if(!rep->hasKeyID())
            rep->setKeyID(CommonEncryption::getKeyID(p_block->p_buffer, p_block->i_buffer));
    }
    else if(encryptionSession && encryptionSession->getMethod() == CommonEncryption::Method::AES_Ctr && source->getChunkType() == adaptive::http::ChunkType::Segment)
    {
        rep->prependInitData(pp_block);
        AP4_MemoryByteStream *decryptedData = encryptionSession->decryptCtr(p_block->p_buffer, p_block->i_buffer, rep->getKeyID());
        if(!decryptedData)
            return;
        copyMdat(decryptedData, p_block);
        decryptedData->Release();
    }
}

StreamFormat SegmentChunk::getStreamFormat() const
{
    return (format == StreamFormat() && rep) ? rep->getStreamFormat() : format;
}

void SegmentChunk::setStreamFormat(const StreamFormat &f)
{
    format = f;
}

void SegmentChunk::setEncryptionSession(CommonEncryptionSession *s)
{
    delete encryptionSession;
    encryptionSession = s;
}
