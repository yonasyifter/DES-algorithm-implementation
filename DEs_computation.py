class DEs_computation:
    def __init__(self):
        self.binary = ''
        self.hex = ''
        self.decimal = ''
    def hex2binary(self, *args):
        for i in range(len(args[0])):
            self.binary += bin(int(args[0][i], 16))[2:].zfill(4)
        return self.binary
    
    def binary2decimal(self,*args):
        self.decimal = int(args[0], 2)
        return self.decimal
    def binary2hex(self, *args):    
        for i in range(len(args[0])):
            self.hex += hex(int(args[0][i], 2))[2:].zfill(1)
        return self.hex
    def decimal2binarybox(self,*args):
        self.binary = ''
        self.binary += bin(int(args[0]))[2:].zfill(4)
        return self.binary

    # Permute function to rearrange the bits
    def permutations(self,k, arr, n):
        self.permutation = ""
        for i in range(0, n):
            self.permutation = self.permutation + k[arr[i] - 1]
        return self.permutation

    # shifting the bits towards left by nth shifts


    def shift_left(self,k, nth_shifts):
        s = ""
        for i in range(nth_shifts):
            for j in range(1, len(k)):
                s = s + k[j]
            s = s + k[0]
            k = s
            s = ""
        return k

    # calculating xow of two strings of binary number a and bD
    def xor(self,a, b):
        self.ans = ""
        for i in range(len(a)):
            if a[i] == b[i]:
                self.ans = self.ans + "0"
            else:
                self.ans = self.ans + "1"
        return self.ans


