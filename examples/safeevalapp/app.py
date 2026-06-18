ALLOWED_EXPRESSIONS = {
    "one": "1 + 1",
    "two": "2 + 2"
}

def internal_calculation():
    # Expression comes from an internal allowlist, not from user input.
    expr = ALLOWED_EXPRESSIONS.get("one", "1 + 1")
    return str(eval(expr))
