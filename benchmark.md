```sh
$ g++ rsa.cpp -lgmpxx -lgmp && ./a.out
Starting the generation of the keypair: Fri Nov  4 19:23:04 2016
START Generation random numbers: Fri Nov  4 19:23:04 2016
END Generation of random numbers: Fri Nov  4 19:23:04 2016
START Find next prime of random numbers: Fri Nov  4 19:23:04 2016
END Find next prime of random numbers: Fri Nov  4 19:24:10 2016
START Find a public exponent: Fri Nov  4 19:24:10 2016
END Find a public exponent: Fri Nov  4 19:24:10 2016
Public exponent: 65537
START Find the private exponent (invert public exponent): Fri Nov  4 19:24:10
2016
END Find the private exponent (invert public exponent): Fri Nov  4 19:24:10 2016
Private exponent: 59970START Write pub key to file: Fri Nov  4 19:24:10 2016
END Write pub key to file: Fri Nov  4 19:24:10 2016
START Write private key to file: Fri Nov  4 19:24:10 2016
END Write private key to file: Fri Nov  4 19:24:10 2016
```
