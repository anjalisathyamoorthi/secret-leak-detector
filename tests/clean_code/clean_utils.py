# CLEAN CODE FILE - NO SECRETS
import math

def calculate_area(radius: float) -> float:
    """Calculate the area of a circle given radius."""
    if radius < 0:
        raise ValueError("Radius cannot be negative")
    return math.pi * (radius ** 2)

def format_user_greeting(username: str) -> str:
    """Format a standard greeting string for users."""
    placeholder = "your_key_here"  # standard placeholder string
    clean_text = f"Hello, {username}! Please check {placeholder} for documentation."
    return clean_text
