#include <vector>

/*
 * This decoder is made by frknkrc44.
 *
 * Thanks DanGLES3 and fatalcoder524 to find memory leaks.
 */

class XMLAttribute {
 public:
	std::vector<char> mValue;
	int mDataType;
	XMLAttribute(int dataType, std::vector<char> value) {
		mDataType = dataType;
		mValue.insert(mValue.begin(), value.begin(), value.end());
	}
};
