#include <cstring>
#include <string>
#include <iostream>
#include <fstream>

static void process( const std::string &content, std::ostream &out )
{
    bool is_comment = false;
    bool is_string = false;
    const char *s = content.c_str();

    while (*s != 0)
    {
        if (is_comment)
        {
            if (*s == '*' && *(s+1) == '/')
            {
                is_comment = false;
                s += 2;
            }
            else
                ++s;
        }
        else
        {
            if (!is_string && *s == '/' && *(s+1) == '*')
            {
                is_comment = true;
                s += 2;
            }
            else
            if (!is_string && *s == '/' && *(s+1) == '/')
            {
                s += 2;
                while (*s != 0 && *s != '\n') ++s;
            }
            else
            if (*s == '"')
            {
                is_string = !is_string;
                out << *s++;
            }
            else
            if (*s == '\r')
                ++s;
            else
                out << *s++;
        }
    }
}

static std::string read_file( const std::string &path )
{
    std::ifstream input(path);
    if (!input.good()) return "";

    std::string output;
    std::string line;
    while (input.good())
    {
        std::getline(input, line);
        output += line;
        output += '\n';
    }
    return output;
}

int main( int argc, char **argv )
{
    if (argc < 3) return 1;

    std::ofstream output(argv[1], std::ios_base::ate);
    if (!output.good()) return 1;
    std::cerr << "Writing to " << argv[1] << std::endl;

    for (int i = 2; i < argc; ++i)
    {
        process(read_file(argv[i]), output);
    }

    return 0;
}