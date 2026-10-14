#include "commands.h"

#include "notebook.h"

#include <chrono>
#include <ostream>
#include <sstream>

namespace {

const auto started = std::chrono::steady_clock::now();

void help(std::ostream& out) {
    out << "  add <text>   add a note\n"
           "  list         show all notes\n"
           "  remove <n>   delete note n\n"
           "  status       show how long the program has been running\n"
           "  quit         exit (Ctrl+D also works)\n";
}

}  // namespace

Outcome run_command(const std::string& line, Notebook& notebook, std::ostream& out) {
    std::istringstream words(line);
    std::string command;
    words >> command;

    if (command.empty()) {
        return Outcome::Continue;
    }
    if (command == "quit" || command == "exit") {
        return Outcome::Quit;
    }

    if (command == "help") {
        help(out);
    } else if (command == "add") {
        std::string text;
        std::getline(words >> std::ws, text);
        if (text.empty()) {
            out << "usage: add <text>\n";
        } else {
            out << "added note " << notebook.add(text) << "\n";
        }
    } else if (command == "list") {
        if (notebook.notes().empty()) {
            out << "no notes yet\n";
        }
        std::size_t number = 1;
        for (const auto& note : notebook.notes()) {
            out << "  " << number++ << ". " << note << "\n";
        }
    } else if (command == "remove") {
        std::size_t number = 0;
        if (words >> number && notebook.remove(number)) {
            out << "removed note " << number << "\n";
        } else {
            out << "no such note\n";
        }
    } else if (command == "status") {
        const auto up = std::chrono::steady_clock::now() - started;
        out << "running for " << std::chrono::duration_cast<std::chrono::seconds>(up).count() << " s, "
            << notebook.notes().size() << " note(s)\n";
    } else {
        out << "unknown command '" << command << "', type help\n";
    }
    return Outcome::Continue;
}
