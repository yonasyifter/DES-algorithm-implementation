
This is DES algorithm implementation to encrypt the message for secure transmission accros the network (transmission media ) in nutshell to satisfay the CIA, 
the implemented algorithm Designed to encode the input message from the command prompt then, 
The message is Encryption process follows the diagram below

![image](https://github.com/yonasyifter/DES-algorithm-implementation/assets/36745357/bda2edfd-4b08-495f-9d47-598a12983a20)


While Decoding the ciphered data (Decoding algorithm) i got some problem it is not implemented as i wish it to be. 
here i may seek your help but never give up fixing it. to implement this what i have done is
##
      self.right_expansion.append(self.calc.permutations(self.rightBlock[i], self.expansion_table, 48))
      self.firstxor = self.calc.xor(self.right_expansion[i], self.key[enc_key])
      self.sbox_compressed.append(self.calc.permutations(self.substitute32(self.firstxor, 6), self.straightper, 32))
      self.rightBlockn.append(self.calc.xor(self.leftBlock[i], self.sbox_compressed[i]))
      self.leftBlockn.append(self.rightBlock[i])
    ##            
![image](https://github.com/yonasyifter/DES-algorithm-implementation/assets/36745357/483b84ec-21eb-4019-a7d4-2cbd64f29b68)
