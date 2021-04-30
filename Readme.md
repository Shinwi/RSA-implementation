# RSA Algorithm Implementation

RSA (Rivest–Shamir–Adleman) is a public-key cryptosystem that is widely used for secure data transmission. It is also one of the oldest. The acronym RSA comes from the surnames of Ron Rivest, Adi Shamir, and Leonard Adleman, who publicly described the algorithm in 1977.
You can read more about it [here](https://en.wikipedia.org/wiki/RSA_(cryptosystem)).


## Libraries Used
* [random.seed](https://docs.python.org/3/library/random.html) and [random.randint](https://docs.python.org/3/library/random.html): <br>used in the *multi_round_miller_rabin()* function in order to generate random numbers to be used as the value of *a*. <br>
( Read more about [Miller-Rabin Primality Test](https://observablehq.com/@beardofdoom/miller-rabin-primality-test) )
* [random.getrandbit](https://docs.python.org/3/library/random.html) : <br>
used in the function *getBigPrime(bitSize)* to generate random number whose size is equivalent to the value of the given bitSize. 

