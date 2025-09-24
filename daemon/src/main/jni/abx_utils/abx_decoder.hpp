#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <vector>

#include "const.h"
#include "xml_element.hpp"

/*
 * This decoder is made by frknkrc44.
 *
 * Thanks DanGLES3 and fatalcoder524 to find memory leaks.
 */

class AbxDecoder {
    public:
    AbxDecoder(std::vector<char> str) {
		mInput = str;
	}

    bool parse() {
        if (!isAbx())
            return false;

        std::cerr << "ABX file found" << std::endl;

        docOpen = false;
        rootClosed = false;
        internedStrings.clear();
		elementStack.clear();

        while (true) {
            char event = readByte();
			int tType = event & 0x0f;
            int dType = event & 0xf0;

            // std::cout << "tType: " << tType << " dType: " << dType << std::endl;

            switch (tType) {
                case TOKEN_ATTRIBUTE: {
                    auto attrName = readInternedString();
                    std::vector<char> value;

                    switch (dType) {
                        case DATA_NULL: {
                            const char* chr = "null";
                            value.insert(value.begin(), chr, chr + strlen(chr));
                            goto finishReadAttr;
                        }
                        case DATA_BOOLEAN_FALSE: {
                            const char* chr = "false";
                            value.insert(value.begin(), chr, chr + strlen(chr));
                            goto finishReadAttr;
                        }
                        case DATA_BOOLEAN_TRUE: {
                            const char* chr = "true";
                            value.insert(value.begin(), chr, chr + strlen(chr));
                            goto finishReadAttr;
                        }
                        case DATA_STRING:
                        case DATA_BYTES_HEX:
                        case DATA_BYTES_BASE64: {
                            value = readString();
                            goto finishReadAttr;
                        }
                        case DATA_STRING_INTERNED: {
                            value = readInternedString();
                            goto finishReadAttr;
                        }
                        case DATA_INT:
                        case DATA_INT_HEX:
                        case DATA_FLOAT: {
                            value = readFromCurPos(4);
                            goto finishReadAttr;
                        }
                        case DATA_LONG:
                        case DATA_LONG_HEX:
                        case DATA_DOUBLE: {
                            value = readFromCurPos(8);
                            goto finishReadAttr;
                        }
                    }

                    finishReadAttr:
                    elementStack.back()->pushAttribute(
                        attrName, std::make_shared<XMLAttribute>(tType, value));
                    continue;
                }
                case TOKEN_START_DOCUMENT: {
                    docOpen = true;
                    continue;
                }
                case TOKEN_END_DOCUMENT: {
                    docOpen = false;
                    continue;
                }
                case TOKEN_START_TAG: {
                    auto tagName = readInternedString();
                    addElementToStack(std::make_shared<XMLElement>(tagName));
                    continue;
                }
                case TOKEN_END_TAG: {
                    auto tagName = readInternedString();
                    auto lastTagName = elementStack.back()->mTagName.data();
                    if (strcmp(tagName.data(), lastTagName) != 0) {
                        std::cerr << "Mismatching tags " << tagName.data() << " - " << lastTagName << std::endl;
                    }

                    if (elementStack.size() == 1) {
                        root = std::move(elementStack.back());
                        docOpen = false;
                        rootClosed = true;
                        goto breakLoopSuccess;
                    }

                    elementStack.pop_back();
                    continue;
                }
                case TOKEN_TEXT:
                case TOKEN_CDSECT:
                case TOKEN_PROCESSING_INSTRUCTION:
                case TOKEN_COMMENT:
                case TOKEN_DOCDECL:
                case TOKEN_IGNORABLE_WHITESPACE: {
                    auto readVal = readString();
                    elementStack.back()->textSections.emplace_back(
                        std::make_shared<XMLAttribute>(tType, readVal));
                    continue;
                }
                default:
                    std::cerr << "Unimplemented type " << (tType >> 4) << " " << dType << std::endl;
                    return false;
            }

            breakLoopSuccess:
            return true;
        }
    }

    std::shared_ptr<XMLElement> root;

    private:
    int curPos = 0;
	std::vector<char> mInput;
    std::vector<std::vector<char>> internedStrings;
    std::vector<std::shared_ptr<XMLElement>> elementStack;
	bool docOpen = false, rootClosed = false;
    const std::vector<char> emptyString;

    std::vector<char> readFromCurPos(int len) {
		// std::cout << "Reading " << len << " bytes of data from " << curPos << std::endl;
		std::vector ret(mInput.begin() + curPos, mInput.begin() + curPos + len);
		curPos += len;
		return ret;
	}

    bool isAbx() {
		// maybe empty?
		if (mInput.size() < 5) return false;

		curPos = 0;
		std::vector<char> headerV = readFromCurPos(4);
		const char* header = reinterpret_cast<const char*>(headerV.data());
		return memcmp(header, startMagic, 4) == 0;
	}

	char readByte() {
		return readFromCurPos(1)[0];
	}

    short readShort() {
		std::vector<char> off = readFromCurPos(2);
        return ((unsigned short) off[0] << 8) | ((unsigned char) off[1]);
	}

    std::vector<char> readString() {
		short len = readShort();
		if (len < 1) {
			return emptyString;
		}

		auto ret = readFromCurPos(len);
        ret.emplace_back(0);
        return ret;
	}

    std::vector<char> readInternedString() {
		short idx = readShort();
        if (idx < 0) {
            std::vector<char> str = readString();
            internedStrings.emplace_back(str);
			return str;
        }

        auto internedStr = internedStrings.begin();
		std::advance(internedStr, idx);
		return *internedStr;
    }

    void addElementToStack(std::shared_ptr<XMLElement> element) {
        if (elementStack.size() > 0) {
            auto lastElement = elementStack.back().get();
            lastElement->subElements.emplace_back(element);
        }

        elementStack.emplace_back(element);
    }
};
