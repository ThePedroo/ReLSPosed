#include "xml_attribute.hpp"

#include <cstring>
#include <map>
#include <vector>

class XMLElement {
 public:
	std::vector<char> mTagName;
	std::map<std::vector<char>, XMLAttribute*>* attributes;
    std::vector<XMLAttribute*> textSections;
	std::vector<XMLElement*> subElements;

	XMLElement* subElementAt(int index) {
		if (index < 0 || index > subElements.size()) return nullptr;

		auto element = subElements.begin();
		std::advance(element, index);
		return *element;
	}

    void pushAttribute(std::vector<char> name, XMLAttribute* attr) {
        attributes->emplace(name, attr);
    }

	XMLAttribute* findAttribute(const char* attr) {
		for (const auto& it : (*attributes)) {
			const char* ch1 = reinterpret_cast<const char*>(it.first.data());
			if (strcmp(ch1, attr) == 0) {
				return it.second;
			}
		}

		return nullptr;
	}

	XMLElement() {
		attributes = new std::map<std::vector<char>, XMLAttribute*>();
	}

	XMLElement(std::vector<char> tagName) {
		attributes = new std::map<std::vector<char>, XMLAttribute*>();
		mTagName.clear();
		mTagName.insert(mTagName.begin(), tagName.begin(), tagName.end());
	}
};
