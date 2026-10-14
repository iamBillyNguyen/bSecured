#pragma once

#include <cstddef>
#include <string>
#include <vector>

// An in-memory list of notes, numbered from 1. Nothing is saved to disk.
class Notebook {
public:
    std::size_t add(std::string text);  // returns the new note's number
    bool remove(std::size_t number);    // false if there is no such note
    const std::vector<std::string>& notes() const { return notes_; }

private:
    std::vector<std::string> notes_;
};
