import DEs_computation as eq
class Key_generation:
    def __init__(self):
        self.permuted_key = ''
        self.key = 'A1B2C3D4E5F67890'  
        self.rightkey = []
        self.leftkey = []   
        self.key_gen = []    
        self.calc = eq.DEs_computation() 
        self.keyp = [57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4]
        
        # Number of bit shifts
        self.shift_table =  [1, 1, 2, 2,
                        2, 2, 2, 2,
                        1, 2, 2, 2,
                        2, 2, 2, 1]

        # Key- Compression Table : Compression of key from 56 bits to 48 bits
        self.key_comp = [14, 17, 11, 24, 1, 5,
                    3, 28, 15, 6, 21, 10,
                    23, 19, 12, 4, 26, 8,
                    16, 7, 27, 20, 13, 2,
                    41, 52, 31, 37, 47, 55,
                    30, 40, 51, 45, 33, 48,
                    44, 49, 39, 56, 34, 53,
                    46, 42, 50, 36, 29, 32]

    
    def encoding_genkey(self):
        # getting 56 bit key from 64 bit using the parity bits
        self.key = self.calc.hex2binary(self.key)
        self.permuted_key = self.calc.permutations(self.key, self.keyp, 56)
        #print("transformed 56 bit")
        #print(self.permuted_key)
        self.leftkey = self.permuted_key[:28]
        self.rightkey = self.permuted_key[28:]
        for i in range(0, 16):
            self.leftkey = self.calc.shift_left(self.leftkey, self.shift_table[i])
            self.rightkey = self.calc.shift_left(self.rightkey, self.shift_table[i])
            self.keying = self.leftkey + self.rightkey
            #print("compressing to 48 bit")
            self.compressed_key = self.calc.permutations(self.keying, self.key_comp, 48)
            #print(self.compressed_key)
            self.key_gen.append(self.compressed_key)
        return self.key_gen
        
   