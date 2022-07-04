#include <fstream>
#include <string>

namespace text_charset_detection

{
	
	bool CheckStreamForUTF8NoBOM(std::ifstream& ifs, std::string& reason);
	bool CheckStreamForUTF8BOM(std::ifstream& ifs, std::string& reason);
	bool CheckStreamForUTF16BOM(std::ifstream& ifs, std::string& reason, bool& bLittleEndian);

}