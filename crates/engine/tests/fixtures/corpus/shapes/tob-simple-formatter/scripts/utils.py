"""Helpers (inert fixture)."""


def capitalize_sentences(text):
    return ". ".join(s.strip().capitalize() for s in text.split("."))
