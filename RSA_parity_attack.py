# import the necessary libraries here
from Crypto.Util import number
from Crypto.Util.number import bytes_to_long, long_to_bytes

class RSA:
    """Implements the RSA public key encryption / decryption."""

    def __init__(self, key_length):
        # define self.p, self.q, self.e, self.n, self.d here based on key_length
        self.p = number.getPrime(key_length)
        self.q = number.getPrime(key_length)
        self.n = self.p * self.q
        self.e = 65537
        self.d = number.inverse(self.e, (self.p-1)*(self.q-1))

    def encrypt(self, binary_data):
        # return encryption of binary_data here
        m = int.from_bytes(binary_data, 'big')
        c = pow(m, self.e, self.n)
        return c

    def decrypt(self, encrypted_int_data):
        # return decryption of encrypted_binary_data here
        m = pow(encrypted_int_data, self.d, self.n)
        return m.to_bytes((m.bit_length() + 7) // 8, 'big')

class RSAParityOracle(RSA):
    """Extends the RSA class by adding a method to verify the parity of data."""

    def is_parity_odd(self, encrypted_int_data):
        # Decrypt the input data and return whether the resulting number is odd
        decrypted_data = self.decrypt(encrypted_int_data)
        return decrypted_data[-1] % 2 == 1


def parity_oracle_attack(ciphertext, rsa_parity_oracle):
    # implement the attack and return the obtained plaintext
    n = rsa_parity_oracle.n
    e = rsa_parity_oracle.e
    c = ciphertext
    k = n.bit_length()
    orig_c = c%n
    
    if n%2==0:
        d = pow(e,-1,n/2-1)
        return pow(c,d,n).to_bytes((k + 7) // 8, 'big')
    
    left=0
    right=n-1
    mid = (left+right)//2

    power = pow(2,e,n)

    while left<right:
        mid = (left+right)//2
        c = (c*power)%n
        if rsa_parity_oracle.is_parity_odd(c):
            left = mid+1
        else:
            right = mid
    for i in range(max(0, left - 1000), left + 1000):
        if pow(i, e, n) == orig_c:
            plaintext = long_to_bytes(i).decode()
            plaintext = plaintext.lstrip(' ')
            print("Plaintext: |",plaintext)
            return plaintext
    return None




def main():
    input_bytes = input("Enter the message: ")

    # Generate a 1024-bit RSA pair    
    rsa_parity_oracle = RSAParityOracle(1024)

    # Encrypt the message
    ciphertext = rsa_parity_oracle.encrypt(input_bytes.encode())
    print("Encrypted message is: ",ciphertext)
    # print("Decrypted text is: ",rsa_parity_oracle.decrypt(ciphertext))

    # Check if the attack works
    plaintext = parity_oracle_attack(ciphertext, rsa_parity_oracle)
    print("Obtained plaintext: ",plaintext)
    assert plaintext == input_bytes.encode()


if __name__ == '__main__':
    main()