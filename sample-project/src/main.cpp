// A small terminal notebook. It keeps running until the user quits, so the
// guard that bSecured injects has a live process to watch.

#include "commands.h"
#include "notebook.h"

#include <iostream>
#include <string>

int main() {
    std::cout << "notes 1.0, type help for commands\n";

    Notebook notebook;
    std::string line;
    for (;;) {
        std::cout << "> " << std::flush;
        if (!std::getline(std::cin, line)) {
            std::cout << "\n";  // Ctrl+D leaves the cursor after the prompt
            break;
        }
        if (run_command(line, notebook, std::cout) == Outcome::Quit) {
            break;
        }
    }
    std::cout << "bye\n";
}
