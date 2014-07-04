#ifndef __SHA1_H__
#define __SHA1_H__

//
// SHA-1 暗号化ハッシュ関数クラス
// FIPS PUB 180-1、US Secure Hash Algorithm 1 (SHA1)、RFC3174 を参照のこと
//
// The MIT License (MIT)
//
// Copyright (c) <2014> chromabox <chromarockjp@gmail.com>
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

#include "crypto_hash.hpp"


class sha1: public crypto_hash
{
public:
	enum{
		DIGEST_LENGTH	= 20,
		BLOCK_SIZE		= 64,
	};	
	
	sha1();
	virtual ~sha1();
	
	virtual bool reset();
	virtual bool update(const void* data,std::size_t len);
	virtual bool final(std::uint8_t* out);
	virtual bool final(std::string &ostr);

	inline virtual int get_digest_size()
	{	return DIGEST_LENGTH; };
	inline virtual int get_block_size()
	{	return BLOCK_SIZE; };
	
private:
	void process();
	
	bool			m_corrupted;				// 壊れフラグ
	std::uint64_t	m_count;					// 総データ長(Byte数)
	std::size_t		m_ix	;					// Block用Index
	std::uint32_t	m_hash[DIGEST_LENGTH/4];	// Hash値
	std::uint8_t	m_blk[BLOCK_SIZE];			// Block
};

	
#endif // __SHA1_H__

