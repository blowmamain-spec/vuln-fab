import ast


def parse(text):
    return ast.literal_eval(text)


def constant():
    return eval("1 + 1")


def evaluate(x):
    return x


value = evaluate(3)
note = "eval(x) in a string"
# eval(x) in a comment
