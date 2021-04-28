
#implement fast modular exponentiation
def fast_modular_exponentiation(a, b, m):
    r = 1
    while b>0:
        if b&1==1: #bitwise AND ppeartion to check if the bit is 1
            r = r*a 
        a = (a*a)%m
        b = b>>1  #shift b by one bit to the right
    return r%m


#print(fast_modular_exponentiation(6,7,90))      #-36
#print(fast_modular_exponentiation(6,73,100))    #-16
#print(fast_modular_exponentiation(536,2000,300)) #-76

#------------------------------------------------------
#miller rabin primality test
def miller_rabin(p, a=2):
    #returns a boolean. 
    #True => n is most likely prime | False => n is not prime
    if(p%2==0):
        return False

    s = 0
    n = p-1
    while(n%2==0):
        n = n//2
        s += 1
        # S is s and D is n
    
    #check if a**d mod p == 1
    if fast_modular_exponentiation(a,n,p)==1:
        return True
    else:
        for i in range(s):
            if fast_modular_exponentiation(a, n*(2**i) ,p) == (p-1):
                return True
    return False        


#print(miller_rabin(13) )      #true
#print(miller_rabin(13, 6) )    #true

#implementation of a multi round miller rabin algorithm
def multi_round_miller_rabin(p, k):
    from random import seed
    from random import randint

    if p%2==0:
        return False
    
    for i in range(k):
        #generate a random number a between 2 and p
        a = randint(2,p-1)
        if (miller_rabin(p, a) == False):
            return False
    
    #if we reach here, p is possibly prime
    return True

#print(miller_rabin(13021,2) )
#print(multi_round_miller_rabin(13021, 10))


#------------------------------------------------------
#extended euclidean algorithm implementation
#get back to this later
def extended_euclidean_algorithm(a,b):
    #returns: [d, x, y] such that d = gcd(a, b) = ax + by 
    if a == 0:
        return b, 0, 1
    else:
        d, x, y = extended_euclidean_algorithm(b%a, a)
        x1= y-(b//a)*x
        y1= x
        return d, x1, y1

#print(extended_euclidean_algorithm(402,123)) #3 15 -49
#print(extended_euclidean_algorithm(40,123))
#print(extended_euclidean_algorithm(4,0))
#------------------------------------------------------


#------------------------------------------------------
def chineese_remainder(c, p, q, d):
    #where c is the cypher text
    # p and q are the prime numbers and d the decryption key

    # dp = d mod p-1
    dp = d%(p-1)
    # dq = d mod q-1
    dq = d%(q-1)
    #mp = c^dp mod p
    mp = fast_modular_exponentiation(c, dp, p)
    #mq = c^dq mod p
    mq = fast_modular_exponentiation(c, dq, p)
    #finding yp and yq
    gcd, yp, yq = extended_euclidean_algorithm(p, q)
    #concluding m
    m = ( (mp*yq*q) + (mq*yp*p) ) % (p*q)
    return m

#-------------------------------------------------------
def getBigPrime(bitSize):
    from random import getrandbits
   
    # Pre generated primes
    first_primes_list = [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97
                   ,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179
                   ,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269
                   ,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367
                   ,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461
                   ,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571
                   ,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661
                   ,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773
                   ,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883
                   ,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997]

    while True:
        number = getrandbits(bitSize)
        if any( number%prime==0 for prime in first_primes_list):
            #number is composite. we can move to the next iteration of the loop
            continue
       
        if miller_rabin(number):
            return number
    

#-------------------------------------------------------
#Key Generation
def key_generation(bitSize):
    #randomly pick two big prime numbers 
    print("\nprinting your keys.....")
    p = getBigPrime(bitSize)
    q = getBigPrime(bitSize)
    print("p is : "+str(p))
    print("q is : "+str(q))

    #set n and phi_n to their values
    n = p*q
    phi_n = (p-1)*(q-1)
    print("n is : "+str(n))
    print("phi_n is :"+str(phi_n))

    #pick e such that phi_n and e are coprime and e<phi_n
    e=2
    while extended_euclidean_algorithm(e, phi_n)[0] != 1:
        e+=1
    print("e : "+str(e))


    #compute d knowing that d*e = 1 mod phi_n
    d = extended_euclidean_algorithm(e, phi_n)[1] % phi_n
    print("d : "+str(d))

    #return the public keys(n,e) and private key d
    return n,e,d


#-------------------------------------------------------

def encrypt(n, e, message):
    #encryptes the message using RSA algorithm
    #returns a cypher text message of type string
    #n,e = keys
    encryptedMessage = [ str(fast_modular_exponentiation(ord(c), e, n) ) for c in message ]
    
    return " ".join(encryptedMessage)

#decryption using fast modular exponentiation
def fme_decrypt(n, d, cypherText ):
    #print("we are decrypthing: "+ cypherText )
    message = [ chr(fast_modular_exponentiation(int(c), d, n) ) 
                for c in cypherText.split(" ") ]
    
    return "".join(message)


#-------------------------------------------------------
def main():
    print("*"*10+"RSA ALGORITHM IMPLEMENTATION IN PYTHON"+"*"*10)
    bitSize = int(input("Please enter the bitsize you wish your keys to be in: "))
    n, e, d =  key_generation(bitSize)
    message = str(input("\nPlease enter a message you wish to encrypt: "))
    print("\nEncrypting..........")
    a = encrypt( n, e , message)
    print("Your encrypted message is:\n"+a )

    
    option = input("would you like to encrypt or decrypt?(e/d)\n")
    while True:
        if option.lower()[0]=='x':
            print("Good bye!")
            break

        if option.lower()[0]=='e':
            message = str(input("\nPlease enter a message you wish to encrypt: "))
            print("\nEncrypting..........")
            a = encrypt( n, e , message)
            print("Your encrypted message is:\n"+a )
        elif option.lower()[0]=='d':
            message = str(input("\nPlease enter a message you wish to decrypt: "))
            print("\nDecrypting..........")
            print("Your decrypted message is: \n"+ fme_decrypt(n, d,  message ) )
        else:
            print("invalid input!\nPlease only enter: e for encryption - d for decryption - x for exiting")
        
        option = input("\nwould you like to encrypt or decrypt?(e/d)\tTo exit, please enter x\nyour answer: ")
    



if __name__=="__main__":
    main()
