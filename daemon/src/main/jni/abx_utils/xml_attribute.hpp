#include <vector>

class XMLAttribute {
 public:
	std::vector<char> mValue;
	int mDataType;
	XMLAttribute(int dataType, std::vector<char> value) {
		mDataType = dataType;
		mValue.insert(mValue.begin(), value.begin(), value.end());
	}
};
