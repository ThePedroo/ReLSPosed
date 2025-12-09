#include <map>
#include <string>
#include <string_view>
#include <vector>
#include <fstream>
#include <sys/stat.h>

#include "logging.h"
#include "abx_utils/abx_decoder.hpp"

#include <stdio.h>
#include <errno.h>
#include <stdbool.h>

#include <rapidxml.hpp>

static const std::string packages_path = "/data/system/packages.xml";
static std::vector<char> LoadFileToStdVector(std::string filename);

// !!! DO NOT REMOVE THIS FUNCTION UNLESS YOU ADDED IT IN RAPIDXML !!!
void rapidxml::parse_error_handler(const char *what, void *where) {
    LOGE("rapidxml Parser error: %s, Start of string: %s\n", what, (char *) where);
}

extern "C" bool get_pkg_from_classpath_arg(const char* classpath_dir, char* package_name, size_t package_name_buffer_size) {
    size_t dir_len = strlen(classpath_dir);
    if(dir_len == 0 || dir_len >= 1024) {
        LOGE("Invalid classpath dir length: %zu", dir_len);
        return false;
    }

    std::vector<char> packagesFile = LoadFileToStdVector(packages_path);

    if(packagesFile.empty()) {
        LOGE("Failed to read packages.xml: %s", strerror(errno));
        return false;
    }

    AbxDecoder decoder(&packagesFile);
    if (!decoder.isAbx()) {
        LOGD("This file is not ABX encoded, trying with XML fallback");

        rapidxml::xml_document document;
        document.parse<0>(packagesFile.data());

        rapidxml::xml_node<> *root_node = document.first_node();
        rapidxml::xml_node<> *current_node = nullptr;

        if (strcmp(root_node->name(), "packages") != 0) {
            LOGE("The root tag is not packages!");

            goto abort_xml_read;
        }

        current_node = root_node->first_node("package");
        while (current_node) {
            {
                rapidxml::xml_attribute<> *name_attr = current_node->first_attribute("name");
                rapidxml::xml_attribute<> *code_path_attr = current_node->first_attribute("codePath");

                if (!name_attr || !code_path_attr) goto continue_xml_loop;

                char* code_path = code_path_attr->value();

                if (strlen(code_path) != dir_len) goto continue_xml_loop;
                if (strncmp(code_path, classpath_dir, dir_len) != 0) goto continue_xml_loop;

                char* name = name_attr->value();
                size_t name_len = strlen(name);

                int copy_len = name_len < package_name_buffer_size - 1 ? static_cast<int>(name_len) : static_cast<int>(package_name_buffer_size - 1);
                memcpy(package_name, name, copy_len * sizeof(char));
                package_name[copy_len] = '\0';

                document.clear();
                return true;
            }

            continue_xml_loop:
            current_node = current_node->next_sibling("package");
        }

        abort_xml_read:
        document.clear();
        return false;
    }

    if (decoder.parse() && decoder.root.get() && strcmp(decoder.root->mTagName.data(), "packages") == 0) {
        for (auto pkg : decoder.root.get()->subElements) {
            if (strcmp(pkg.get()->mTagName.data(), "package") != 0) continue;
            XMLAttribute* nameAttr = pkg.get()->findAttribute("name");
            XMLAttribute* codePathAttr = pkg.get()->findAttribute("codePath");
            if (nameAttr == NULL || codePathAttr == NULL) continue;
            
            const char* name = reinterpret_cast<const char*>(nameAttr->mValue.data());
			const char* codePath = reinterpret_cast<const char*>(codePathAttr->mValue.data());
			if (strlen(codePath) != dir_len) continue;
			if (strncmp(codePath, classpath_dir, dir_len) != 0) continue;

            int copy_len = strlen(name) < package_name_buffer_size - 1 ? static_cast<int>(strlen(name)) : static_cast<int>(package_name_buffer_size - 1);
            memcpy(package_name, name, copy_len * sizeof(char));
            package_name[copy_len] = '\0';
            return true;
        }
    } else {
        if (decoder.root) {
            LOGE("Wrong ABX File; rootElement: %s", decoder.root->mTagName.data());
        } else {
            LOGE("Failed to parse ABX file");
        }
        return false;
    }
    
    return false;
}

static std::vector<char> LoadFileToStdVector(std::string filename) {
	std::vector<char> out;
	size_t len;

	// We can try to load the XML directly...
	LOGD("LoadFileToStdVector loading filename: '%s' directly\n", filename.c_str());

	struct stat st;
	if (stat(filename.c_str(),&st) != 0) {
		// This isn't always an error, sometimes we request files that don't exist.
		return out;
	}

	len = (size_t)st.st_size;

	// open the file
	std::ifstream file(filename, std::ios_base::in | std::ios_base::binary);

	if(!file) {
		LOGE("LoadFileToStdVector failed to open '%s' - (%s)\n", filename.c_str(), strerror(errno));
		return out;
	}

	// read the file to the vector of chars
	size_t cnt = 0;
	char c;
	while(cnt < len) {
		file.get(c);
		out.push_back(c);
		cnt++;
	}
    LOGD("LoadFileToStdVector Read filename: '%s' successfull\n", filename.c_str());
	file.close();
	return out;
}