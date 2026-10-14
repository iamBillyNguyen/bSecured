#include "notebook.h"

#include <utility>

std::size_t Notebook::add(std::string text) {
    notes_.push_back(std::move(text));
    return notes_.size();
}

bool Notebook::remove(std::size_t number) {
    if (number == 0 || number > notes_.size()) {
        return false;
    }
    notes_.erase(notes_.begin() + static_cast<std::ptrdiff_t>(number - 1));
    return true;
}
