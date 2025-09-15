#include <cstring>
#include <iostream>
#include <map>
#include <vector>

#include "const.h"
#include "xml_element.hpp"

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
                            value.insert(value.begin(), chr, chr + strlen(chr) - 1);
                            goto finishReadAttr;
                        }
                        case DATA_BOOLEAN_FALSE: {
                            const char* chr = "false";
                            value.insert(value.begin(), chr, chr + strlen(chr) - 1);
                            goto finishReadAttr;
                        }
                        case DATA_BOOLEAN_TRUE: {
                            const char* chr = "true";
                            value.insert(value.begin(), chr, chr + strlen(chr) - 1);
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
                    XMLAttribute* attr = new XMLAttribute(tType, value);
                    elementStack.back()->pushAttribute(attrName, attr);
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
                    addElementToStack(new XMLElement(tagName));
                    continue;
                }
                case TOKEN_END_TAG: {
                    auto tagName = readInternedString();
                    auto lastTagName = elementStack.back()->mTagName.data();
                    if (strcmp(tagName.data(), lastTagName) != 0) {
                        std::cerr << "Mismatching tags " << tagName.data() << " - " << lastTagName << std::endl;
                    }

                    if (elementStack.size() == 1) {
                        root = elementStack.back();
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
                    elementStack.back()->textSections
                        .push_back(new XMLAttribute(tType, readVal));
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

    XMLElement* root;

    private:
    int curPos = 0;
	std::vector<char> mInput;
    std::vector<std::vector<char>> internedStrings;
    std::vector<XMLElement*> elementStack;
	bool docOpen = false, rootClosed = false;

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
		return strcmp(header, startMagic) == 0;
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
			return *(new std::vector<char>());
		}

		auto ret = readFromCurPos(len);
        ret.push_back(0);
        return ret;
	}

    std::vector<char> readInternedString() {
		short idx = readShort();
        if (idx < 0) {
            std::vector<char> str = readString();
            internedStrings.push_back(str);
			return str;
        }

        auto internedStr = internedStrings.begin();
		std::advance(internedStr, idx);
		return *internedStr;
    }

    void addElementToStack(XMLElement* element) {
        if (elementStack.size() > 0) {
            XMLElement* lastElement = elementStack.back();
            lastElement->subElements.push_back(element);
        }

        elementStack.push_back(element);
    }
};
