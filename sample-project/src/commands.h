#pragma once

#include <iosfwd>
#include <string>

class Notebook;

enum class Outcome { Continue, Quit };

// Runs one line typed by the user against the notebook, writing any reply to out.
Outcome run_command(const std::string& line, Notebook& notebook, std::ostream& out);
