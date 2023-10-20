from secrets import choice
from string import digits, ascii_letters, punctuation
def generator(num_of_chr:int) -> str:
    """Generates a random list of numbers, letters and symbols"""
    sbol_list = digits + ascii_letters + punctuation
    result = "".join(choice(sbol_list) for _ in range(num_of_chr))
    result.replace("\\", "")
    return result