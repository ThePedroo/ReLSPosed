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

static const std::string packages_path = "/data/system/packages.xml";
static std::vector<char> LoadFileToStdVector(std::string filename);

extern "C" bool get_pkg_from_classpath_arg(const char* classpath_dir, char* package_name, size_t package_name_buffer_size) {    
    size_t dir_len = strlen(classpath_dir);
    if(dir_len == 0 || dir_len >= 1024) {
        LOGE("Invalid classpath dir length: %zu", dir_len);
        return false;
    }

    std::vector<char> packagesFile = LoadFileToStdVector(packages_path);

    if(packagesFile.size() < 1)
    {
        LOGE("Failed to read packages.xml: %s", strerror(errno));
        return false;
    }
    
    AbxDecoder decoder(packagesFile);
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