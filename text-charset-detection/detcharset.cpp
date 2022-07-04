#include "detcharset.h"
#include <memory>
#include <bitset>
#include <cassert>

namespace text_charset_detection
{
	namespace detail {
		constexpr size_t UTF8_MAX_CHAR_SIZE = 4;							// longest UTF-8 char size in bytes
		constexpr size_t UTF8_NO_BOM_TEXT_SAMPLE_SIZE = 0; // 1024;			// how many bytes to read from the beginning of a text file, 0 means to read whole file to decide if it's in UTF-8 -- can lead to bad_alloc for large files
		constexpr size_t UTF8_TINY_MODE_SIZE_LIMIT = 1'000'000'000;						// non-tiny mode means checking sample buffer for 0...N-4 bytes, omiting interleaved buffer-end checks, speeds up by around 10%, according to my measures
		constexpr bool UTF8_SUBCLASSIFY_TOO_LONG_SEQUENCES = true;			// should it distinguish between different >4 byte (invalid) UTF-8 sequences by size (next checked position for valid UTF-8 char depends on this)
		constexpr bool UTF8_DETAILED_ERROR_LIST = true;						// should it not stop early if evidence for non-UTF-8 found (true: detailed report for all UTF-8 errors found, much slower)

		typedef unsigned char utf8_checking_unit_t;

		inline std::string UcharToBinStr(utf8_checking_unit_t uchar)
		{
			return std::bitset<sizeof(utf8_checking_unit_t) * 8>(uchar).to_string();
		}

		// will return "[00000000 11111111 00000000 11111111]" for ({0x00, 0xFF, 0x00, 0xFF}, 4)
		inline std::string UcharSeqToBinStr(const utf8_checking_unit_t* ucharPtr, size_t len)
		{
			if (len == 0)
				return "[]";
			std::string retval = "[" + UcharToBinStr(ucharPtr[0]);
			for (size_t i = 1; i < len; ++i)
				retval += " " + UcharToBinStr(ucharPtr[i]);
			retval += "]";
			return retval;
		}
		
		// UTF8CharXXXX functions return true if valid char found at specific position, UTF8InvalidXXXX functions return true on different specific UTF-8 errors
		// Note: all specific UTF-8 error checks assume the leading/continuation bytes are OK (a call to UTF8InvalidLeadingOrContinuation() has to precede them to ensure this),
		// while UTF8CharXXXX functions have this check built-in. This speeds up quick decide mode (UTF8_DETAILED_ERROR_LIST==false) where UTF8InvalidXXXX() functions, especially 
		// UTF8InvalidLeadingOrContinuation() is not called. 

		// checks whether ucharPtr points to standard 7-bit ASCII char, excluding most control codes (but including TAB, CR, LF)
		// assumes ucharPtr[0] readable
		inline bool UTF8CharASCII7(const utf8_checking_unit_t* ucharPtr)
		{
			// Unicode code point range: U+000000 (00)...U+00007F (7F) with some exceptions
			return
				ucharPtr[0] == 0x09 ||									// 7-bit ASCII, excluding control code 0x7F and non-common control codes below 0x20
				ucharPtr[0] == 0x0A ||
				ucharPtr[0] == 0x0D ||
				(0x20 <= ucharPtr[0] && ucharPtr[0] <= 0x7E);
		}

		// checks whether ucharPtr points to a value >=127 or <32 (excluding common control chars TAB, CR, LF)
		// assumes ucharPtr[0] readable
		inline bool UTF8InvalidControlChar(const utf8_checking_unit_t* ucharPtr)
		{
			return
				((ucharPtr[0] & 0b10000000) == 0) &&
				!UTF8CharASCII7(ucharPtr);
		}

		// checks if ucharPtr points to a valid 2-byte UTF-8 sequence (non-overlong)
		// assumes ucharPtr[0...1] readable
		inline bool UTF8CharValid2Bytes(const utf8_checking_unit_t* ucharPtr)
		{
			// Unicode code point range: U+000080 (C2 80)...U+0007FF (DF BF)
			return														//			[0]			[1]				data bits
				(0xC2 <= ucharPtr[0] && ucharPtr[0] <= 0xDF) &&			// from:	0b110'00010	0b10'000000	--> 00010 000000 = 0x80 
				(0x80 <= ucharPtr[1] && ucharPtr[1] <= 0xBF);			// to:		0b110'11111	0b10'111111	--> 11111 111111 = 0x7FF
		}

		// checks if ucharPtr points to 2-byte invalid overlong UTF8 sequence
		// assumes ucharPtr[0] readable (needs to check only first byte, ucharPtr[1] is indifferent)
		inline bool UTF8Invalid2BytesOverlong(const utf8_checking_unit_t* ucharPtr)
		{
			return
				(0xC0 <= ucharPtr[0] && ucharPtr[0] <= 0xC1);			// everything starts with 0b110'00000 or 0b110'00001 can only be U+000000...U+00007F, those are overlong representations
		}

		// checks whether ucharPtr points to valid 3-byte UTF-8 sequence (non-overlong)
		// assumes ucharPtr[0...2] readable
		inline bool UTF8CharValid3Bytes(const utf8_checking_unit_t* ucharPtr)
		{
			// Unicode code point range: U+000800 (E0 A0 80)...U+007FFF (EF BF BF)
			return
				(((0xE1 <= ucharPtr[0] && ucharPtr[0] <= 0xEC) || ucharPtr[0] == 0xEE || ucharPtr[0] == 0xEF) &&	// sequences starting with 0xE1...0xEC, 0xEE, 0xEF
					(0x80 <= ucharPtr[1] && ucharPtr[1] <= 0xBF) &&													// cannot be invalid if the following 2 are
					(0x80 <= ucharPtr[2] && ucharPtr[2] <= 0xBF))													// continuation bytes (0b10'xxxxxx)
				||
				(ucharPtr[0] == 0xE0 &&																				// sequences starting with 0xE0 = 1110'0000 can be invalid 3-byte overlongs
					(0xA0 <= ucharPtr[1] && ucharPtr[1] <= 0xBF) &&													// [0] 1110'0000 [1] 10'100000 [2] 10'000000 --> 0000 100000 000000 = 0x800
					(0x80 <= ucharPtr[2] && ucharPtr[2] <= 0xBF))													// [0] 1110'0000 [1] 10'111111 [2] 10'111111 --> 0000 111111 111111 = 0xFFF, between these we're fine
				||
				(ucharPtr[0] == 0xED &&																				// sequences starting with 0xED = 1110'1101 can be U+00D800–U+00DFFF which are invalid UTF-16 surrogate halves
					(0x80 <= ucharPtr[1] && ucharPtr[1] <= 0x9F) &&													// [0] 1110'1101 [1] 10'000000 [2] 10'000000 --> 1101 000000 000000 = 0xD000
					(0x80 <= ucharPtr[2] && ucharPtr[2] <= 0xBF));													// [0] 1110'1101 [1] 10'011111 [2] 10'111111 --> 1101 011111 111111 = 0xD7FF, between these we're fine
		}

		// determines if ucharPtr points to a 3-byte overlong invalid UTF-8 sequence
		// assumes ucharPtr[0...1] readable (ucharPtr[2] is indifferent)
		inline bool UTF8Invalid3BytesOverlong(const utf8_checking_unit_t* ucharPtr)
		{
			return
				ucharPtr[0] == 0xE0 &&
				(0x80 <= ucharPtr[1] && ucharPtr[1] <= 0x9F);													// sequences starting with 0xE0 = 1110'0000 can be invalid 3-byte overlongs if next byte is between 0b10'000000 and 0b10'011111
		}

		// determines if ucharPtr points to a 3-byte invalid UTF-8 sequence that specifies UTF-16 surrogate half
		// assumes ucharPtr[0...1] readable (ucharPtr[2] is not checked)
		inline bool UTF8Invalid3BytesSurrogateHalf(const utf8_checking_unit_t* ucharPtr)
		{
			return
				ucharPtr[0] == 0xED &&
				(0xA0 <= ucharPtr[1] && ucharPtr[1] <= 0xBF);													// sequences starting with 0xED = 1110'1101 can be invalid UTF-16 surrogate halves if next byte is between 0b10'100000 and 0b10'111111
		}

		// checks whether ucharPtr points to valid 4-byte UTF-8 sequence (non-overlong)
		// assumes ucharPtr[0...3] readable
		inline bool UTF8CharValid4Bytes(const utf8_checking_unit_t* ucharPtr)
		{
			// Unicode code point range: U+010000 (F0 90 80 80)...U+10FFFF (F4 8F BF BF)
			return
				// planes 1-3
				(ucharPtr[0] == 0xF0 &&																					// sequnces starting with 0xF0 = 11110'000 can be invalid 4-byte overlongs
					(0x90 <= ucharPtr[1] && ucharPtr[1] <= 0xBF) &&														// [0] 11110'000 [1] 10'010000 [2] 10'000000 [3] 10'000000 --> 000 010000 000000 000000 = 0x10000
					(0x80 <= ucharPtr[2] && ucharPtr[2] <= 0xBF) &&														// [0] 11110'000 [1] 10'111111 [2] 10'111111 [3] 10'011111 --> 000 111111 111111 111111 = 0x3FFFF, between these we're fine
					(0x80 <= ucharPtr[3] && ucharPtr[3] <= 0xBF))
				||
				// planes 4-15
				((0xF1 <= ucharPtr[0] && ucharPtr[0] <= 0xF3) &&														// all sequences starting with 0xF1,0xF2,0xF3 cannot be invalid if 
					(0x80 <= ucharPtr[1] && ucharPtr[1] <= 0xBF) &&														// the following 3 are continuation bytes (0b10'xxxxxx);
					(0x80 <= ucharPtr[2] && ucharPtr[2] <= 0xBF) &&
					(0x80 <= ucharPtr[3] && ucharPtr[3] <= 0xBF))
				||
				// plane 16
				(ucharPtr[0] == 0xF4 &&																					// sequences starting with 0xF4 could specify invalid code points above U+10FFFF
					(0x80 <= ucharPtr[1] && ucharPtr[1] <= 0x8F) &&														// [0] 11110'100 [1] 10'000000 [2] 10'000000 [3] 10'000000 --> 100 000000 000000 000000 = 0x100000
					(0x80 <= ucharPtr[2] && ucharPtr[2] <= 0xBF) &&														// [0] 11110'100 [1] 10'001111 [2] 10'111111 [3] 10'111111 --> 100 001111 111111 111111 = 0x10FFFF,
					(0x80 <= ucharPtr[3] && ucharPtr[3] <= 0xBF));														// between these we're fine
		}

		// determines if ucharPtr points to a 4-byte overlong invalid UTF-8 sequence
		// assumes ucharPtr[0...1] readable (ucharPtr[2,3] is indifferent)
		inline bool UTF8Invalid4BytesOverlong(const utf8_checking_unit_t* ucharPtr)
		{
			return
				ucharPtr[0] == 0xF0 &&
				(0x80 <= ucharPtr[1] && ucharPtr[1] <= 0xBF);														// sequences starting with 0xF0 = 11110'000 can be invalid 4-byte overlongs if next byte is between 0b10'000000 and 0b10'001111
		}

		// determines if ucharPtr points to a 4-byte UTF-8 sequence that specifies Unicode code points above U+10FFFF (and has a leading byte 0xF4)
		// assumes ucharPtr[0...3] readable (ucahrPtr[2,3] is checked only to extract code point number)
		inline bool UTF8InvalidCodePoint4BytesF4(const utf8_checking_unit_t* ucharPtr, unsigned int& codePoint)
		{
			if (ucharPtr[0] == 0xF4 &&																				// sequences starting with 0xF4 can specify too high code points if next byte is between 0b10'010000 and 0b10'111111
				(0x90 <= ucharPtr[1] && 0xBF <= ucharPtr[1]))
			{
				codePoint =
					((static_cast<unsigned int>(ucharPtr[1]) & 0b00'111111) << 12) |
					((static_cast<unsigned int>(ucharPtr[2]) & 0b00'111111) << 6) |
					((static_cast<unsigned int>(ucharPtr[3]) & 0b00'111111));

				return true;
			}
			else
			{
				return false;
			}
		}

		// determines if ucharPtr points to a 4-byte UTF-8 sequence that specifies Unicode code points above U+10FFFF (cases where the leading byte is other than 0xF4)
		// assumes ucharPtr[0] readable (ucahrPtr[1...3] is indifferent here)
		inline bool UTF8InvalidCodePoint4BytesNonF4(const utf8_checking_unit_t* ucharPtr)
		{
			return
				0xF5 <= ucharPtr[0] && ucharPtr[0] <= 0xF7;															// all sequences starting with 0xF5..0xF7 specify too high code points
		}

		// checks if ucharPtr points to a valid UTF-8 leading byte
		// assumes ucharPtr[0] readable, sets continuationBytesRequired output parameter to how many continuation bytes should follow leading byte (if valid)
		inline void UTF8IsValidLeadingByte(const utf8_checking_unit_t* ucharPtr, bool& bValid, size_t& utf8sequenceLength)
		{
			utf8_checking_unit_t leadingByte = ucharPtr[0];
			if (UTF8_SUBCLASSIFY_TOO_LONG_SEQUENCES)
			{
				if ((leadingByte >> 2) == 0b111110)			// 0b111110xx (0xF8, 0xF9, 0xFA, 0xFB)
				{
					utf8sequenceLength = 5;
					bValid = false;
					return;
				}
				if ((leadingByte >> 1) == 0b1111110)		// 0b1111110x (0xFC, 0xFD)
				{
					utf8sequenceLength = 6;
					bValid = false;
					return;
				}
				if ((leadingByte >> 1) == 0b1111111)		// 0b1111111x (0xFE, 0xFF)
				{
					utf8sequenceLength = 1;
					bValid = false;
					return;
				}
			}
			leadingByte >>= 3;
			if (leadingByte == 0b11110)				// 0b11110xxx
			{
				utf8sequenceLength = 4;
				bValid = true;
				return;
			}
			leadingByte >>= 1;
			if (leadingByte == 0b1110)				// 0b1110xxxx
			{
				utf8sequenceLength = 3;
				bValid = true;
				return;
			}
			leadingByte >>= 1;
			if (leadingByte == 0b110)				// 0b110xxxxx
			{
				utf8sequenceLength = 2;
				bValid = true;
				return;
			}
			leadingByte >>= 2;
			if (leadingByte == 0)					// 0b0xxxxxxx
			{
				utf8sequenceLength = 1;
				bValid = true;
				return;
			}

			utf8sequenceLength = 1;
			bValid = false;
		}

		// checks if ucharPtr points to a valid UTF-8 continuation byte
		// assumes ucharPtr[0] readable
		inline bool UTF8IsContinuationByte(const utf8_checking_unit_t* ucharPtr)
		{
			return (ucharPtr[0] & 0b11'000000) == 0b10'000000;
		}

		// Checks if bytes following ucharPtr are all valid continuation bytes 
		// assumes ucharPtr[0...bufferReamins-1] readable
		// requiredContinuationBytes: as it is specified by leading byte
		// bufferRemains: nr of bytes safe to read from ucharPtr, including ucharPtr[0], must be at least 1
		// returns:
		//	- bMismatchFound = true, if not enough continuation bytes found following leading byte (but all where readable till the mismatch)
		//	- bTruncated = true, if ran out of buffer space verifying continuation bytes
		//	- whereToContinueChecking is where the next non-continuation byte (supposedly leading byte) is guessed
		inline void UTF8InvalidNrOfContinuationBytes(const utf8_checking_unit_t* ucharPtr, size_t requiredContinuationBytes, size_t bufferRemains, bool& bTruncated, bool& bMismatchFound, const utf8_checking_unit_t*& whereToContinueChecking)
		{
			size_t checkUntil;
			if (requiredContinuationBytes + 1 > bufferRemains)
			{
				bTruncated = true;
				whereToContinueChecking = ucharPtr + bufferRemains;
				checkUntil = bufferRemains;
			}
			else
			{
				bTruncated = false;
				checkUntil = requiredContinuationBytes + 1;
			}

			// starts from 1, ucharPtr[0] is leading byte
			for (size_t idx = 1; idx < checkUntil; ++idx)
			{
				if (!UTF8IsContinuationByte(&ucharPtr[idx]))
				{
					bMismatchFound = true;
					whereToContinueChecking = &ucharPtr[idx];
					break;
				}
			}
		}

		// Combines UTF8IsValidLeadingByte() and UTF8InvalidNrOfContinuationBytes() together to rule out primary UTF-8 error scenarios:
		// invalid leading byte or invalid number of continuation bytes after leading byte
		inline bool UTF8InvalidLeadingOrContinuation(const utf8_checking_unit_t *& ucharPtr, const utf8_checking_unit_t * charBufStartPtr, const utf8_checking_unit_t * charBufEndPtr, std::string& reason)
		{
			const std::string position = std::to_string(ucharPtr - charBufStartPtr);

			bool bLeadingByteValid = false;
			size_t utf8sequenceLength = -1000;
			UTF8IsValidLeadingByte(ucharPtr, bLeadingByteValid, utf8sequenceLength);
			if (!bLeadingByteValid)
			{
				size_t bytesToRead;
				std::string suffix;
				if (utf8sequenceLength > charBufEndPtr - ucharPtr)
				{
					bytesToRead = charBufEndPtr - ucharPtr;
					suffix = "<end-of-buffer>";
				}
				else
				{
					bytesToRead = utf8sequenceLength;
					suffix = "";
				}
				reason += "Invalid leading byte found at " + position + " (assumed length=" + std::to_string(utf8sequenceLength) + "): " + UcharSeqToBinStr(ucharPtr, bytesToRead) + suffix + "\n";
				ucharPtr += bytesToRead;
				return true;
			}
			bool bTruncated = false, bMisMatch = false;
			const utf8_checking_unit_t* ucharPtrUpdate = nullptr;
			UTF8InvalidNrOfContinuationBytes(ucharPtr, utf8sequenceLength - 1, charBufEndPtr - ucharPtr, bTruncated, bMisMatch, ucharPtrUpdate);
			if (bTruncated)
			{
				reason += "Invalid nr of continuation bytes after leading byte [possible truncation] at " + position + ": " + UcharSeqToBinStr(ucharPtr, charBufEndPtr - ucharPtr) + "<end-of-buffer>\n";
				ucharPtr = ucharPtrUpdate;
				return true;
			}
			if (bMisMatch)
			{
				reason += "Invalid nr of continuation bytes after leading byte [unexpected non-continuation byte] at " + position + ": " + UcharSeqToBinStr(ucharPtr, utf8sequenceLength) + "\n";
				ucharPtr = ucharPtrUpdate;
				return true;
			}
			return false;
		}

		// charBufEndPtr: should point to the first invalid position after the buffer (in consistance with usual C++ for loops)
		template <bool bBufferEndCheck>
		inline void UTF8CharValidate(const utf8_checking_unit_t *& ucharPtr, const utf8_checking_unit_t * charBufEndPtr, bool& bThisCharValidUTF8, bool& bThisCharValidASCII7, std::string& reason)
		{
			if (bBufferEndCheck && ucharPtr > charBufEndPtr - 1)
			{
				// No room for checking 1-byte --> no evidence, exit & leave bValidXXXX untouched 
				// (should never reach this point)
				assert(false);
				return;
			}

			if (UTF8CharASCII7(ucharPtr))
			{
				// Valid 1-byte UTF-8 --> step pointer & exit, leaving bValidXXXX untouched
				bThisCharValidASCII7 = true;
				bThisCharValidUTF8 = true;
				ucharPtr += 1;
				return;
			}

			bThisCharValidASCII7 = false;

			if (bBufferEndCheck && ucharPtr > charBufEndPtr - 2)
			{
				bThisCharValidUTF8 = false;
				reason += "Not valid 1-byte UTF-8 at the end, no room for testing any 2-byte UTF-8 sequence --> considered non-UTF-8\n";
				return;
			}
			if (UTF8CharValid2Bytes(ucharPtr))
			{
				// Valid 2-byte UTF-8 --> step pointer & exit, leaving bValidXXXX untouched
				bThisCharValidUTF8 = true;
				ucharPtr += 2;
				return;
			}

			if (bBufferEndCheck && ucharPtr > charBufEndPtr - 3)
			{
				bThisCharValidUTF8 = false;
				reason += "Not valid 1 or 2-byte UTF-8 at the end, no room for testing any 3-byte UTF-8 sequence --> considered non-UTF-8\n";
				return;
			}

			if (UTF8CharValid3Bytes(ucharPtr))
			{
				// Valid 3-byte UTF-8 --> step pointer & exit, leaving bValidXXXX untouched
				bThisCharValidUTF8 = true;
				ucharPtr += 3;
				return;
			}

			if (bBufferEndCheck && ucharPtr > charBufEndPtr - 4)
			{
				bThisCharValidUTF8 = false;
				reason += "Not valid 1,2, or 3-byte UTF-8 at the end, no room for testing any 4-byte UTF-8 sequence --> considered non-UTF-8\n";
				return;
			}

			if (UTF8CharValid4Bytes(ucharPtr))
			{
				// Valid 3-byte UTF-8 --> step pointer & exit, leaving bValidXXXX untouched
				bThisCharValidUTF8 = true;
				ucharPtr += 4;
				return;
			}

			// No more valid UTF-8 options --> considered non-UTF-8
			bThisCharValidUTF8 = false;
			reason += "Found invalid UTF-8 sequence\n";
		}

		// charBufEndPtr: should point to the first invalid position after the buffer (in consistance with usual C++ for loops)
		inline void UTF8CheckErrors(const utf8_checking_unit_t *& ucharPtr, const utf8_checking_unit_t * charBufStartPtr, const utf8_checking_unit_t * charBufEndPtr, std::string& reason)
		{
			if (ucharPtr > charBufEndPtr - 1)
			{
				// No room for checking 1-byte --> no evidence, exit & leave bValidXXXX untouched
				return;
			}

			const std::string position = std::to_string(ucharPtr - charBufStartPtr);

			if (UTF8InvalidLeadingOrContinuation(ucharPtr, charBufStartPtr, charBufEndPtr, reason))
			{
				return;
			}

			if (UTF8InvalidControlChar(ucharPtr))
			{
				reason += "Invalid 1 byte sequence: control char found at " + position + ": " + UcharSeqToBinStr(ucharPtr, 1) + "\n";
				ucharPtr += 1;
				return;
			}

			if (ucharPtr > charBufEndPtr - 2)
			{
				reason += "Unknown UTF-8 error: checked all 1-byte possibilities, reached end of buffer at position " + position + ": " + UcharSeqToBinStr(ucharPtr, charBufEndPtr - ucharPtr) + "<end-of-buffer>\n";
				ucharPtr = charBufEndPtr;
				return;
			}
			if (UTF8Invalid2BytesOverlong(ucharPtr))
			{
				reason += "Invalid 2-byte overlong found at " + position + ": " + UcharSeqToBinStr(ucharPtr, 2) + "\n";
				ucharPtr += 2;
				return;
			}

			if (ucharPtr > charBufEndPtr - 3)
			{
				reason += "Unknown UTF-8 error: checked all 1,2-byte possibilities, reached end of buffer at position " + position + ": " + UcharSeqToBinStr(ucharPtr, charBufEndPtr - ucharPtr) + "<end-of-buffer>\n";
				ucharPtr = charBufEndPtr;
				return;
			}
			if (UTF8Invalid3BytesOverlong(ucharPtr))
			{
				reason += "Invalid 3-byte overlong found at " + position + ": " + UcharSeqToBinStr(ucharPtr, 3) + "\n";
				ucharPtr += 3;
				return;
			}
			if (UTF8Invalid3BytesSurrogateHalf(ucharPtr))
			{
				reason += "Invalid UTF-16 surrogate half found at " + position + ": " + UcharSeqToBinStr(ucharPtr, 3) + "\n";
				ucharPtr += 3;
				return;
			}

			if (ucharPtr > charBufEndPtr - 4)
			{
				reason += "Unknown UTF-8 error: checked all 1,2,3-byte possibilities, reached end of buffer at position " + position + ": " + UcharSeqToBinStr(ucharPtr, charBufEndPtr - ucharPtr) + "<end-of-buffer>\n";
				ucharPtr = charBufEndPtr;
				return;
			}

			if (UTF8Invalid4BytesOverlong(ucharPtr))
			{
				reason += "Invalid 4-byte overlong found at " + position + ": " + UcharSeqToBinStr(ucharPtr, 4) + "\n";
				ucharPtr += 4;
				return;
			}
			unsigned int dummy;
			if (UTF8InvalidCodePoint4BytesF4(ucharPtr, dummy))
			{
				reason += "Invalid code point specified by 4-byte encoding (F4) at " + position + ": " + UcharSeqToBinStr(ucharPtr, 4) + "\n";
				ucharPtr += 4;
				return;
			}
			if (UTF8InvalidCodePoint4BytesNonF4(ucharPtr))
			{
				reason += "Invalid code point specified by 4-byte encoding (non-F4) at " + position + ": " + UcharSeqToBinStr(ucharPtr, 4) + "\n";
				ucharPtr += 4;
				return;
			}

			size_t safeBufDumpSize = 16 < charBufEndPtr - ucharPtr ? 16 : charBufEndPtr - ucharPtr;
			reason += "Unknown UTF-8 error: checked all known UTF-8 error classes, none of them matched at " + position + " (assumed length=1): " + UcharSeqToBinStr(ucharPtr, safeBufDumpSize) + "\n";
			ucharPtr += 1;
		}

		template <bool bBufferEndCheck>
		inline void CheckStreamForUTF8NoBOMInternal(utf8_checking_unit_t const * const bufferStart, utf8_checking_unit_t const * const stopPos, bool& bValidUTF8, bool& b7bitASCIIOnly, std::string& reason)
		{
			bValidUTF8 = true;
			b7bitASCIIOnly = true;
			utf8_checking_unit_t const * ucharPtr = bufferStart;

			while (ucharPtr < stopPos)
			{
				bool bThisCharValid, bThisCharValid7bitASCII;
				UTF8CharValidate<bBufferEndCheck>(ucharPtr, stopPos, bThisCharValid, bThisCharValid7bitASCII, reason);
				bValidUTF8 &= bThisCharValid;
				b7bitASCIIOnly &= bThisCharValid7bitASCII;
				if (!bValidUTF8 && !UTF8_DETAILED_ERROR_LIST)
					break;
				if (!bThisCharValid)
					UTF8CheckErrors(ucharPtr, bufferStart, stopPos, reason);
			}
		}

		std::unique_ptr<utf8_checking_unit_t[]> ReadSampleToBuffer(std::ifstream& ifs, size_t& allocBufferSize, size_t& usableBufferSize)
		{
			static_assert(sizeof(char) == 1, "This code assumes sizeof(char) == 1");
			static_assert(sizeof(utf8_checking_unit_t) == sizeof(char), "This code assumes char and utf8_checking_unit_t have the same size");

			// tell approximate stream size
			const std::streampos savedStreamPos = ifs.tellg();
			ifs.seekg(0, std::ios::end);
			const size_t bytesTillEndOfStream = ifs.tellg();
			ifs.seekg(savedStreamPos);

			// determine buffer size to use
			allocBufferSize =
				UTF8_NO_BOM_TEXT_SAMPLE_SIZE == 0 || UTF8_NO_BOM_TEXT_SAMPLE_SIZE > bytesTillEndOfStream ?
				bytesTillEndOfStream :
				UTF8_NO_BOM_TEXT_SAMPLE_SIZE;
			std::unique_ptr<utf8_checking_unit_t[]> sampleTextBuffer = std::make_unique<utf8_checking_unit_t[]>(allocBufferSize);

			// try read allocBufferSize bytes
			ifs.read((char*)sampleTextBuffer.get(), allocBufferSize);
			usableBufferSize = ifs.gcount();
			if (usableBufferSize < allocBufferSize)
			{
				// If stream is in text mode, line ending conversions may have occurred during read(), possibly shrinking readble data.
				// In this case we were trying to read at least 1 more bytes than the stream has, so not only eofbit, but also failbit has set.
				// We need to clear this before trying to rewind.
				ifs.clear();
			}

			ifs.seekg(savedStreamPos);
			return std::move(sampleTextBuffer);
		}
		
		constexpr int SIGNATURE_CHECK_RESULT_FAIL = 0;
		constexpr int SIGNATURE_CHECK_RESULT_NOT_FOUND = 1;
		constexpr int SIGNATURE_CHECK_RESULT_FOUND = 2;
		template <size_t N>
		int CheckStreamForSignature(std::ifstream& ifs, std::string& reason, const utf8_checking_unit_t(&signature)[N])
		{
			static_assert(sizeof(char) == 1, "This code assumes sizeof(char) == 1");
			static_assert(sizeof(utf8_checking_unit_t) == sizeof(char), "This code assumes char and utf8_checking_unit_t have the same size");
			
			if (ifs.fail())
			{
				reason += "stream.fail()\n";
				return SIGNATURE_CHECK_RESULT_FAIL;
			}
			if (ifs.eof())
			{
				reason += "stream empty\n";
				return SIGNATURE_CHECK_RESULT_FAIL;
			}

			const std::streampos savedStreamPos = ifs.tellg();

			utf8_checking_unit_t readBuf[N];

			ifs.read((char*)&readBuf[0], sizeof(readBuf));

			if (ifs.gcount() < N)
			{
				ifs.clear();
				ifs.seekg(savedStreamPos);
				return SIGNATURE_CHECK_RESULT_NOT_FOUND;
			}

			for (size_t idx = 0; idx < sizeof(signature); ++idx)
			{
				if (readBuf[idx] != signature[idx])
				{
					if (ifs.fail())
					{
						ifs.clear();
					}
					ifs.seekg(savedStreamPos);
					return SIGNATURE_CHECK_RESULT_NOT_FOUND;
				}
			}

			// we consumed signature, so no rewind to savedStreamPos
			return SIGNATURE_CHECK_RESULT_FOUND;
		}

	} // namespace text_charset_detection::detail
	
	bool CheckStreamForUTF8NoBOM(std::ifstream& ifs, std::string& reason)
	{
		size_t allocBufferSize = -1;
		size_t readCount = -1;
		std::unique_ptr<detail::utf8_checking_unit_t[]> sampleTextBuffer = detail::ReadSampleToBuffer(ifs, allocBufferSize, readCount);

		bool bValidUTF8 = true;
		bool b7bitASCIIOnly = true;
		detail::utf8_checking_unit_t const * const bufferStart = sampleTextBuffer.get();


		if (readCount >= detail::UTF8_TINY_MODE_SIZE_LIMIT) [[likely]]
		{
			// non-tiny mode, cut 4 bytes from the end, then go through text without pointer checking (this leaves the last 4 bytes out from checking, but faster)
			detail::CheckStreamForUTF8NoBOMInternal<false>(bufferStart, bufferStart + readCount - detail::UTF8_MAX_CHAR_SIZE, bValidUTF8, b7bitASCIIOnly, reason);
		}
		else
		{
			reason += "text is shorter than a predefined limit, checking entire buffer\n";
			detail::CheckStreamForUTF8NoBOMInternal<true>(bufferStart, bufferStart + readCount, bValidUTF8, b7bitASCIIOnly, reason);
		}

		if (b7bitASCIIOnly)
			reason += "ASCII 7-bit text\n";

		if (bValidUTF8)
			reason += "sample of input contains only valid UTF-8 characters\n";

		if (b7bitASCIIOnly)
		{
			// it's technically UTF-8, but conversion is not necessary
			return false;
		}

		return bValidUTF8;
	}

	// prerequisite: stream has to be at 0 reading position
	bool CheckStreamForUTF8BOM(std::ifstream& ifs, std::string& reason)
	{
		assert(static_cast<size_t>(ifs.tellg()) == 0);
		// checks for UTF-8 representation of U+00FEFF (0xEF 0xBB 0xBF) at the beginning of the stream
		constexpr detail::utf8_checking_unit_t UTF8BOM[] = { 0xEF, 0xBB, 0xBF };

		const int checkResult = detail::CheckStreamForSignature(ifs, reason, UTF8BOM);
		switch (checkResult)
		{
		case detail::SIGNATURE_CHECK_RESULT_FAIL:
			return false;
		case detail::SIGNATURE_CHECK_RESULT_NOT_FOUND:
			reason += "No UTF-8 BOM found\n";
			return false;
		case detail::SIGNATURE_CHECK_RESULT_FOUND:
			reason += "UTF-8 BOM found\n";
			return true;
		default:
			throw std::logic_error("text_charset_detection::detail::SIGNATURE_CHECK_RESULT_xxxx out of bounds (a)");
		}
	}

	// prerequisite: stream has to be at 0 reading position
	bool CheckStreamForUTF16BOM(std::ifstream& ifs, std::string& reason, bool& bLittleEndian)
	{
		assert(static_cast<size_t>(ifs.tellg()) == 0);
		// checks for UTF-8 representation of U+00FEFF (0xEF 0xBB 0xBF) at the beginning of the stream
		constexpr detail::utf8_checking_unit_t UTF16LE_BOM[] = { 0xFF, 0xFE };
		constexpr detail::utf8_checking_unit_t UTF16BE_BOM[] = { 0xFE, 0xFF };

		const int checkResultLE = detail::CheckStreamForSignature(ifs, reason, UTF16LE_BOM);
		switch (checkResultLE)
		{
		case detail::SIGNATURE_CHECK_RESULT_FAIL:
			return false;
		case detail::SIGNATURE_CHECK_RESULT_NOT_FOUND:
		{
			const int checkResultBE = detail::CheckStreamForSignature(ifs, reason, UTF16BE_BOM);
			switch (checkResultBE)
			{
			case detail::SIGNATURE_CHECK_RESULT_FAIL:
				return false;
			case detail::SIGNATURE_CHECK_RESULT_NOT_FOUND:
				reason += "No UTF-16 BOM found\n";
				return false;
			case detail::SIGNATURE_CHECK_RESULT_FOUND:
				reason += "UTF-16 BE BOM found\n";
				bLittleEndian = false;
				return true;
			default:
				throw std::logic_error("text_charset_detection::detail::SIGNATURE_CHECK_RESULT_xxxx out of bounds (b)");
			}
		}
		case detail::SIGNATURE_CHECK_RESULT_FOUND:
			reason += "UTF-16 LE BOM found\n";
			bLittleEndian = true;
			return true;
		default:
			throw std::logic_error("text_charset_detection::detail::SIGNATURE_CHECK_RESULT_xxxx out of bounds (c)");
		}
	}

} // namespace text_charset_detection
