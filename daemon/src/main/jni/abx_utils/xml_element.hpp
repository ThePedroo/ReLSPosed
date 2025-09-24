#include "xml_attribute.hpp"

#include <cstring>
#include <map>
#include <memory>
#include <vector>

/*
 * This decoder is made by frknkrc44.
 *
 * Thanks DanGLES3 and fatalcoder524 to find memory leaks.
 */

class XMLElement {
 public:
	std::vector<char> mTagName;
	std::map<std::vector<char>, std::shared_ptr<XMLAttribute>> attributes;
    std::vector<std::shared_ptr<XMLAttribute>> textSections;
	std::vector<std::shared_ptr<XMLElement>> subElements;

	XMLElement* subElementAt(size_t index) {
		if (index < 0 || index >= subElements.size()) return nullptr;

		auto element = subElements.begin();
		std::advance(element, index);
		return (*element).get();
	}

    void pushAttribute(std::vector<char> name, std::shared_ptr<XMLAttribute> attr) {
        attributes.emplace(name, attr);
    }

	XMLAttribute* findAttribute(const char* attr) {
		for (const auto& it : attributes) {
			const char* ch1 = reinterpret_cast<const char*>(it.first.data());
			if (memcmp(ch1, attr, strlen(ch1)) == 0) {
    			return it.second.get();
			}
		}

		return nullptr;
	}

	XMLElement(std::vector<char> tagName) {
		mTagName.clear();
		mTagName.insert(mTagName.begin(), tagName.begin(), tagName.end());
	}
};
