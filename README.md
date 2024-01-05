# Lab Assignment on Key Distribution

## Distributed Symmetric Key Distribution

1. In the communication scenario, both parties, A and B, have established a shared session master key $K_M$.
2. Upon successful distribution of the session key $K_S$, A encrypts a specific file (`test-1.txt`) using $K_S$ and sends it to B.
3. B decrypts the received ciphertext using $K_S$ and verifies if the decrypted plaintext matches the original file.

## Asymmetric Key Distribution Using Public Key Certificates

1. In the communication scenario, both parties, A and B, trust a third party, the Certificate Authority (CA), which is responsible for generating individual public key certificates for each of them. 
2. Upon exchanging their public key certificates, A and B independently verify the authenticity of each other's certificates (assuming A and B have already obtained CA's public key).
3. A encrypts a predefined integer data $X$ (e.g., 100) using B's public key and sends it to B.
4. B decrypts it with its private key to retrieve data X, applies a predetermined function $F$ (e.g., $F(X) = 2*X$) to it, encrypts the result using A's public key, and sends it back.
5. A, after decrypting it with its private key and obtaining remote computed $F(x)$, compares it with the locally computed $F(X)$. If they match, it indicates the success of the public key distribution.
6. A encrypts an image file (`test_pic.bmp`) using B's public key and sends it to B.
7. B decrypts it and compares the decrypted image with the original to verify consistency. The entire encryption/decryption duration, denoted as time $T_1$, is recorded.

## Symmetric Key Distribution Utilizing Asymmetric Cryptography

1. Within the framework of asymmetric cryptographic techniques, A distributes the symmetric key $K_S$ to B, adhering to the established symmetric key distribution protocol.
2. A encrypts an image file (test_pic.bmp) using the symmetric key $K_S$ and transmits it to B.
3. Upon receipt, B decrypts the file and compares it with the original to verify consistency. The entire encryption/decryption duration, denoted as time $T_2$, is recorded.
4. Undertake a comparative analysis of the time durations $T_1$ and $T_2$ to evaluate the efficiency of both cryptographic methods.
