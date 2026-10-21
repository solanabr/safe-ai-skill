"""Text formatter (inert fixture)."""
from utils import capitalize_sentences


def format_text(text):
    return capitalize_sentences(" ".join(text.split()))
