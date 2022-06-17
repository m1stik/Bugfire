import random
import uuid

class PasswordGenerator:

    def __init__(self):
        self.nr_letters = 6
        self.nr_symbols = 2
        self.nr_numbers = 4
        self.letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        self.numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        self.symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

    def generate(self):
        password_unmixed = []

        #Generating sequence of chars
        for step in range(1, self.nr_letters + 1):
            password_unmixed.append(random.choice(self.letters))
        for step in range(1, self.nr_symbols + 1):
            password_unmixed.append(random.choice(self.symbols))
        for step in range(1, self.nr_numbers + 1):
            password_unmixed.append(random.choice(self.numbers))

        #Shuffling the sequence
        random.shuffle(password_unmixed)

        #Converting list to string
        password_string = ''.join(password_unmixed)

        #Password output
        return str(password_string)
    
    def generate_hash(self):
        return str(uuid.uuid4().hex)