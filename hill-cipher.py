import numpy as np
from Crypto.Util.number import inverse

def encrypt(plaintext,key):
    # convert key to matrix of 3*3
    key = np.array([ord(i)-65 for i in key]).reshape(3,3)
    plaintext_length = len(plaintext)
    if plaintext_length%3 != 0:
        plaintext = plaintext+'X'*(3-(plaintext_length%3))
    plaintext = np.array([ord(i)-65 for i in plaintext]).reshape(-1,3)
    plaintext = plaintext.T

    ciphertext = np.dot(key,plaintext)
    ciphertext = np.remainder(ciphertext,26)
    ciphertext = ciphertext.T
    ciphertext = ''.join([chr(i+65) for i in ciphertext.flatten()])
    return ciphertext

def cofactor(matrix):

    # n = len(matrix)
    # if n == 1:
    #     return matrix
    # cofactor_matrix = np.zeros((n,n))
    # for i in range(n):
    #     for j in range(n):
    #         minor = np.delete(matrix,i,0)
    #         minor = np.delete(minor,j,1)
    #         # print(minor)
    #         cofactor_matrix[i,j] = (-1)**(i+j+2)*np.linalg.det(minor)
    #         # print(cofactor_matrix)
    # # cofactor_matrix = np.remainder(cofactor_matrix,26)
    cofactor_matrix = np.linalg.inv(matrix).T * np.linalg.det(matrix)
    cofactor_matrix =np.round(cofactor_matrix).astype(int)
    cofactor_matrix = cofactor_matrix.T
    return cofactor_matrix




def discover_key(plaintext,ciphertext):
    # get the first 9 characters of plaintext and ciphertext
    plaintext = plaintext[:9]
    ciphertext = ciphertext[:9]
    plaintext = np.array([ord(i)-65 for i in plaintext]).reshape(-1,3).T
    # print("Plaintext: ",plaintext)
    ciphertext = np.array([ord(i)-65 for i in ciphertext]).reshape(-1,3).T
    # print("Ciphertext: ",ciphertext)
    # print("Cofactor: ",cofactor)
    plain_cofactor = cofactor(plaintext)%26
    
    # plain_cofactor = np.remainder(plain_cofactor,26)
    # print("Cofactor: ",plain_cofactor)
    # print("Cofactor: ",cipher_cofactor)
    plain_cofactor = plain_cofactor.astype(int)
    plain_det = int(np.linalg.det(plaintext))
    # print(cipher_det.dtype)
    # print(plain_det)
    det_inverse = inverse(plain_det,26)

    plain_inverse = np.multiply(plain_cofactor,det_inverse)
    plain_inverse = np.remainder(plain_inverse,26)
    key = np.dot(ciphertext,plain_inverse)
    key = key.astype(int)
    key = np.remainder(key,26)
    # print(key)
    key = ''.join([chr(i+65) for i in key.flatten()])
    return key

# testcases = open('testcases.txt','r').read().split('\n')
# count=1
# for testcase in testcases[:-1]:
#     test = testcase.split(' ')
#     if discover_key(test[0],test[1]) != test[2]:
#         print('Encryp failed-',count)
#     print('Testcase-',count,'Passed')
#     count=count+1


# NJIVZZUFUPRJAK GSQNTTNKAXRPHRL XDZGUJQCD




