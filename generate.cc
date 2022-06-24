/*
 *   Copyright 2016-2022 Bruno Ribeiro
 *   <https://github.com/brunexgeek/webster>
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <cstring>
#include <string>
#include <iostream>
#include <fstream>
#include <list>

static const char *LICENSE =
"/*\n"
" *   Copyright 2022 Bruno Ribeiro\n"
" *   <https://github.com/brunexgeek/webster>\n"
" *\n"
" *   Licensed under the Apache License, Version 2.0 (the \"License\");\n"
" *   you may not use this file except in compliance with the License.\n"
" *   You may obtain a copy of the License at\n"
" *\n"
" *       http://www.apache.org/licenses/LICENSE-2.0\n"
" *\n"
" *   Unless required by applicable law or agreed to in writing, software\n"
" *   distributed under the License is distributed on an \"AS IS\" BASIS,\n"
" *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n"
" *   See the License for the specific language governing permissions and\n"
" *   limitations under the License.\n"
" */\n";

static void process( const std::string &content, std::ostream &out )
{
    bool is_comment = false;
    bool is_string = false;
    const char *s = content.c_str();
    std::string line;

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
                std::string value;
                while (*s != 0 && *s != '\n') value += *s++;
                if (value.find("AUTO-REMOVE") != std::string::npos)
                    line.clear();
            }
            else
            if (*s == '"')
            {
                is_string = !is_string;
                line += *s++;
            }
            else
            if (*s == '\r')
                ++s;
            else
            if (*s == '\n')
            {
                if (line.find("<webster.hh>") != std::string::npos)
                    out << "#include \"webster.hh\"\n";
                else
                    out << line << '\n';
                line.clear();
                ++s;
            }
            else
                line += *s++;
        }
    }
    if (!line.empty()) out << line;
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

    std::list<std::string> defs;
    std::list<std::string> files;
    std::string path;
    for (int i = 1; i < argc; ++i)
    {
        if (argv[i][0] == '-' && argv[i][1] == 'D')
            defs.push_back(argv[i] + 2);
        else
        {
            if (path.empty())
                path = argv[i];
            else
                files.push_back(argv[i]);
        }
    }

    //std::cerr << "Path: " << path << std::endl;
    //for (std::string &value : defs) std::cerr << "Definition: " << value << std::endl;
    //for (std::string &value : files) std::cerr << "File: " << value << std::endl;

    std::ofstream output(path, std::ios_base::ate);
    if (!output.good()) return 1;
    std::cerr << "Writing to " << path << std::endl;

    output << LICENSE << "\n// Auto-generated file\n";
    for (std::string &def : defs)
        output << "#define " << def << '\n';
    for (std::string &path : files)
        process(read_file(path), output);

    return 0;
}