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

#include <cassert>
#include <fstream>
#include <iostream>
#include <string>

#define DEBUG 1

using namespace adaptive::playlist;
using namespace adaptive::encryption;
using namespace adaptive;

static int segmentNr = 1;

namespace
{
    void writeToFile(const std::string &filename, block_t *data)
    {
        std::ofstream logfile ("I:/" + filename + ".mp4", std::ofstream::out | std::ofstream::binary);
        if (logfile.is_open())
        {
            logfile.write(reinterpret_cast<char *>(data->p_buffer), data->i_buffer);
            logfile.close();
        }
    }

    void writeToFile(const std::string &filename, AP4_MemoryByteStream *data)
    {
        std::ofstream logfile ("I:/" + filename + ".mp4", std::ofstream::out | std::ofstream::binary);
        if (logfile.is_open())
        {
            logfile.write(reinterpret_cast<const char *>(data->GetData()), data->GetDataSize());
            logfile.close();
        }
    }

    void writeToLog(const std::string& text)
    {
        std::ofstream logfile ("I:/log.txt", std::ofstream::out | std::ofstream::app);
        if (logfile.is_open())
        {
            logfile << text << std::endl;
            logfile.flush();
            logfile.close();
        }
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
#if (DEBUG == 1)
        writeToLog("void SegmentChunk::onDownload(block_t **pp_block) 00");
#endif
    
    if(encryptionSession && encryptionSession->getMethod() == CommonEncryption::Method::AES_128)
    {
        decrypt(pp_block);
    }
    else if(encryptionSession && encryptionSession->getMethod() == CommonEncryption::Method::AES_Ctr && source->getChunkType() == adaptive::http::ChunkType::Init)
    {
        block_t *p_block = *pp_block;
        
        rep->saveInitData(pp_block);
        if(!rep->hasKeyID())
            rep->setKeyID(CommonEncryption::getKeyID(p_block->p_buffer, p_block->i_buffer));

        AP4_MemoryByteStream *modifiedInit = CommonEncryption::modifyInit(p_block->p_buffer, p_block->i_buffer);
        if(!modifiedInit)
            return;
        
        block_Release(p_block);
        p_block = block_Alloc(modifiedInit->GetDataSize());
        if(p_block)
            memcpy(p_block->p_buffer, modifiedInit->GetData(), p_block->i_buffer);
        modifiedInit->Release();
    }
    else if(encryptionSession && encryptionSession->getMethod() == CommonEncryption::Method::AES_Ctr && source->getChunkType() == adaptive::http::ChunkType::Segment)
    {
        block_t *p_block = *pp_block;

#if (DEBUG == 1)
        writeToLog("void SegmentChunk::onDownload(block_t **pp_block) 01");
#endif
        rep->prependInitData(pp_block);
#if (DEBUG == 1)
        writeToLog("void SegmentChunk::onDownload(block_t **pp_block) 02");
#endif
        AP4_MemoryByteStream *decryptedData = encryptionSession->decryptCtr(p_block->p_buffer, p_block->i_buffer, rep->getKeyID());
#if (DEBUG == 1)
        writeToLog("void SegmentChunk::onDownload(block_t **pp_block) 03");
#endif
        if(!decryptedData)
            return;
#if (DEBUG == 1)
        writeToLog("void SegmentChunk::onDownload(block_t **pp_block) 04");
#endif
        block_Release(p_block);
#if (DEBUG == 1)
        writeToLog("void SegmentChunk::onDownload(block_t **pp_block) 05");
#endif
        p_block = block_Alloc(decryptedData->GetDataSize());
#if (DEBUG == 1)
        writeToLog("void SegmentChunk::onDownload(block_t **pp_block) 06");
#endif
        if(p_block)
        {
            memcpy(p_block->p_buffer, decryptedData->GetData(), p_block->i_buffer);
#if (DEBUG == 1)
            writeToLog("void SegmentChunk::onDownload(block_t **pp_block) 07");
#endif
        }
#if (DEBUG == 1)
        writeToLog("void SegmentChunk::onDownload(block_t **pp_block) 08");
#endif
        decryptedData->Release();
#if (DEBUG == 1)
        writeToLog("void SegmentChunk::onDownload(block_t **pp_block) Done! Wrote " + std::to_string(p_block->i_buffer) + " bytes.");
#endif
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
