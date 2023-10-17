import DEs_computation as eq
import DEs_Key_gen as key
class DEs_Encoding:
    def __init__(self, plaintext:str):
        self.plaintext = plaintext
        self.calc = eq.DEs_computation()
        self.key = key.Key_generation()
        self.permutedtext = []
        self.binaryText = []
        self.leftBlock = []
        self.rightBlock = []
        self.right_expansion = []
        self.sbox_compressed = []
        self.leftBlockn = []
        self.rightBlockn = []
        self.encrypted_data = ''
        self.compressed = None
        self.accumulated = {}
        self.ciphered_data = []
        self.inverse_perm_data = []
        self.initial_perm =[58, 50, 42, 34, 26, 18, 10, 2,
                            60, 52, 44, 36, 28, 20, 12, 4,
                            62, 54, 46, 38, 30, 22, 14, 6,
                            64, 56, 48, 40, 32, 24, 16, 8,
                            57, 49, 41, 33, 25, 17, 9, 1,
                            59, 51, 43, 35, 27, 19, 11, 3,
                            61, 53, 45, 37, 29, 21, 13, 5,
                            63, 55, 47, 39, 31, 23, 15, 7]
        self.expansion_table =  [32, 1, 2, 3, 4, 5, 4, 5,
                                 6, 7, 8, 9, 8, 9, 10, 11,
                                 12, 13, 12, 13, 14, 15, 16, 17,
                                 16, 17, 18, 19, 20, 21, 20, 21,
                                 22, 23, 24, 25, 24, 25, 26, 27,
                                 28, 29, 28, 29, 30, 31, 32, 1]
        self.final_inverse_perm =[40, 8, 48, 16, 56, 24, 64, 32,
                                  39, 7, 47, 15, 55, 23, 63, 31,
                                  38, 6, 46, 14, 54, 22, 62, 30,
                                  37, 5, 45, 13, 53, 21, 61, 29,
                                  36, 4, 44, 12, 52, 20, 60, 28,
                                  35, 3, 43, 11, 51, 19, 59, 27,
                                  34, 2, 42, 10, 50, 18, 58, 26,
                                  33, 1, 41, 9, 49, 17, 57, 25]
        self.straightper =[16,  7, 20, 21,
                           29, 12, 28, 17,
                           1, 15, 23, 26,
                           5, 18, 31, 10,
                           2,  8, 24, 14,
                           32, 27,  3,  9,
                           19, 13, 30,  6,
                           22, 11,  4, 25]

        self.sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
            
                    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
            
                    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
            
                    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
            
                    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
            
                    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
            
                    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
            
                    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

    def Encoding_data(self):
        print(self.plaintext)
        self.plaintextHex = self.plaintext.encode('utf-8').hex()
        self.binarydata = self.calc.hex2binary(self.plaintextHex)
        block_64bit = 64
        for block in range(0, int((len(self.binarydata)/block_64bit)+1)):
            self.binaryText.append(self.binarydata[block*block_64bit: block_64bit* (block+1)])
        last = len(self.binaryText[int(len(self.binarydata)/block_64bit)])
        if last < 64:
            for i in range(64 - last):
                self.binaryText[int(len(self.binarydata)/block_64bit)]= self.binaryText[int(len(self.binarydata)/block_64bit)] + '0'
        print("The binary form of the Message:")
        print(self.binaryText)
        for i in range(len(self.binaryText)):
            self.perm= self.calc.permutations(self.binaryText[i], self.initial_perm, 64)
            self.permutedtext.append(self.perm)
        for block_seg in range(len(self.permutedtext)):
            self.leftBlock.append(self.permutedtext[block_seg][: 32])
            self.rightBlock.append(self.permutedtext[block_seg][32:64])
        self.key = self.key.encoding_genkey()
        for enc_key in range(16):
            # expand the 32 left and right blocks of data to 48 bit data
            #using the expansion table declared above
            self.leftBlockn = []
            self.rightBlockn = []
            for i in range(len(self.rightBlock)):
                self.right_expansion.append(self.calc.permutations(self.rightBlock[i], self.expansion_table, 48))
                self.firstxor = self.calc.xor(self.right_expansion[i], self.key[enc_key])
                self.sbox_compressed.append(self.calc.permutations(self.substitute32(self.firstxor, 6), self.straightper, 32))
                self.rightBlockn.append(self.calc.xor(self.leftBlock[i], self.sbox_compressed[i]))
                self.leftBlockn.append(self.rightBlock[i])
            self.leftBlock = self.leftBlockn
            self.rightBlock = self.rightBlockn
            
        for i in range(len(self.leftBlock)):
            self.encrypted_data = self.encrypted_data + (self.leftBlock[i] + self.rightBlock[i])  
        self.inverse_perm_data = self.calc.permutations(self.encrypted_data, self.final_inverse_perm, 64)
            
        print('The Encrypted Message Is --->')
        print(self.inverse_perm_data)
        ans = input("Do you want to decode the cipher?(y/n)")
        if ans == 'y':
            print("Decoding The Encrypted data --->")
            self.Decoding_algorithm(self.encrypted_data)
        else:
            import sys
            sys.exit()
            
    def Decoding_algorithm(self, ciphered):
        self.data = ciphered
        self.ciphered_binary = []
        self.left_binarycipher = []
        self.right_binarycipher = []
        self.right_block = []
        self.left_block = []
        self.decryption = ''
        block_64bit = 64
        for block in range(0, int((len(self.data)/block_64bit)+1)):
            self.ciphered_binary.append(self.data[block*block_64bit: block_64bit* (block+1)])
        last = len(self.ciphered_binary[int(len(self.data)/block_64bit)])
        if last < 64:
            for i in range(64 - last):
                self.ciphered_binary[int(len(self.data)/block_64bit)]= self.ciphered_binary[int(len(self.data)/block_64bit)] + '0'
        for block in range(0, int((len(self.ciphered_binary)/block_64bit)+1)):
            self.left_binarycipher.append(self.ciphered_binary[block][:32])
            self.right_binarycipher.append(self.ciphered_binary[block][32:])
        #self.key = self.key.encoding_genkey()
        for enc_key in range(16):
            '''for i in range(len(self.left_binarycipher)):
                self.right_cipher = self.calc.xor(self.accumulated[i], self.right_binarycipher[i])
                self.right_cipher = self.calc.permutations(self.right_cipher, self.straightper, 32)
                self.right_cipher = self.substitute48(self.right_cipher)
                self.right_cipher = self.calc.permutations(self.right_cipher, self.expansion_table, 48)
                self.firstxor_key = self.calc.xor(self.right_cipher, self.key[16-enc_key])
                self.right_cipher = self.convert32(self.firstxor_key)
                self.leftBlockn.append(self.accumulated[i])
                self.rightBlockn.append(self.right_cipher)  '''
            #for i in range(len(self.left_binarycipher)):
            for i in range(int(len(self.left_binarycipher))):          
                self.right_block = self.left_binarycipher[i]
                self.left_block = self.calc.xor(self.right_binarycipher[i],self.sbox_compressed[15-enc_key])
                self.left_binarycipher[i] = self.left_block
                self.right_binarycipher[i] = self.right_block
                if enc_key > 14:
                    msg = self.left_binarycipher[i] + self.right_binarycipher[i]
                    self.decryption = self.decryption + msg
                else:
                    pass
        print(self.decryption)           

        
    def substitute32(self,first, n):
        self.data = first
        self.substitution = ''
        for i in range(int(len(self.data)/n)):
            segment = self.data[i*n:(i+1)*n]
            #print(i ,"  " ,segment)
            row =int(self.calc.binary2decimal(segment[0]+segment[5]))
            column =int(self.calc.binary2decimal(segment[1:5]))
            for row_index in range(4):
                for col_index in range(16):
                    if row_index == row and col_index == column:
                        self.substitution = self.substitution + (self.calc.decimal2binarybox(self.sbox[i][row_index][col_index]))   
                    else:
                        pass
        self.compressed = self.substitution
        self.substitution = ''   
        return self.compressed
    
    
    
    
    
    '''    
    def convert32(self, ciphered48):
        self.ciphered48 = ciphered48
        self.ciphered32 = ''
        self.returned = ''
        first = 0
        begin = 0
        second = 1
        for i in range (8):
            if (second <= 32):
                first = first + 4
                second = second + 4
                self.ciphered32 = self.ciphered32 + self.ciphered48[begin:first]
                begin = first+2
            else:
                break
        for i in range (32):
            if (i <= 30):
                self.returned = self.returned + self.ciphered32[i+1]
            else:
                self.returned = self.returned + self.ciphered32[i]
        return self.returned
                '''

    '''
    def substitute48(self, cipher):
        self.data = cipher
        self.substitution = ''
        for i in range(int(len(self.data)/4)):
            segment = self.data[i*4:(i+1)*4]
            for j in range(4):
                for k in range(16):
                    find = self.calc.binary2decimal(segment[i])
                    if self.sbox[i][j][k] == find:
                        row =  self.calc.decimal2binarybox(j)
                        col = self.calc.decimal2binarybox(k)
                        self.substitution = self.substitution + (row[0]+col+row[1])
                    else:
                        pass
            return self.substitution
                        
            '''
        
if __name__ == "__main__":
    message = input("Enter Your Message to encrypt:    ")
    encoding = DEs_Encoding(message)
    encoding.Encoding_data()
   