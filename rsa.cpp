#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <stdio.h>
#include "gmp/gmp.h"

#define FILENAME_TEMP_P "temp_p"
#define FILENAME_TEMP_Q "temp_q"
#define FILENAME_PRIVATE_KEY "rsa.private"
#define FILENAME_PUBLIC_KEY "rsa.public"

#define DEBUG 1
#define log_debug gmp_printf

#define DEFAULT_PRIME_LENGTH 512

using namespace std;

/**
 * Writes a randomly generated bit_length length binary number
 * to the filename
 */
void write_random_to_file(const char * filename, int bit_length) {
	ofstream fout;
	fout.open(filename, ios::out | ios::app);
	fout << 1;
	for(int i = 1; i < bit_length; ++i) {
		fout << (rand() % 2);
	}
	fout.close();
}

/**
 * Store the values of p, q, Dp, Dq and q_inv (mod p) in the private key
 * file.
 * Resource:
 * https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm
 * RFC 3447 - Section 3.2 - 2nd representation
 */
void write_private_key_to_file(mpz_t &p, mpz_t &q, mpz_t &private_exponent) {
	FILE * stream;
	stream = fopen(FILENAME_PRIVATE_KEY, "w");

	gmp_fprintf(stream, "%Zx\n%Zx\n", p, q);

	mpz_t temp;
	mpz_init(temp);

	mpz_sub_ui(temp, p, 1);
	mpz_mod(temp, private_exponent, temp);
	gmp_fprintf(stream, "%Zx\n", temp);

	mpz_sub_ui(temp, q, 1);
	mpz_mod(temp, private_exponent, temp);
	gmp_fprintf(stream, "%Zx\n", temp);

	mpz_invert(temp, q, p);
	gmp_fprintf(stream, "%Zx\n", temp);

	fclose(stream);

	mpz_clear(temp);
}

/**
 * Get the stored private key parameters from the private key file
 */
void read_private_key_from_file(const char * filename, 
																mpz_t &p, 
																mpz_t &q, 
																mpz_t &private_exponent, 
																mpz_t &dp, 
																mpz_t &dq, 
																mpz_t &g_inv) {
	FILE * stream;
	stream = fopen(filename, "r");

	// TODO: Use gmp_fscanf

	fclose(stream);
}

void write_public_key_to_file(mpz_t modulus, long unsigned int public_exponent) {
	FILE * stream;
	stream = fopen(FILENAME_PUBLIC_KEY, "w");

	// TODO: Use gmp_fprintf to write the modulus and the public exponent to the
	// file

	fclose(stream);
}

void generate_key_pair(int PRIMES_BIT_LENGTH) {
	
	mpz_t temp_1, prime_p, prime_q, totient, private_exponent;

	// Generate random P and Q values
	
	write_random_to_file(FILENAME_TEMP_P, PRIMES_BIT_LENGTH);
	write_random_to_file(FILENAME_TEMP_Q, PRIMES_BIT_LENGTH);

	mpz_init(prime_p);
	mpz_init(prime_q);

	mpz_init(temp_1);

	// Read the random temp values from the file
	// Find the next smallest prime P and Q

	FILE * stream;

	stream = fopen(FILENAME_TEMP_P, "r");
	mpz_inp_str(temp_1, stream, 2);
	fclose(stream);
	mpz_nextprime(prime_p, temp_1);

	stream = fopen(FILENAME_TEMP_Q, "r");
	mpz_inp_str(temp_1, stream, 2);
	fclose(stream);
	mpz_nextprime(prime_q, temp_1);

	// TODO: Find a safe prime
	// A safe prime is one which is equal to 2*p + 1 where p is also a prime
	// number.

	// Calculate the totient

	mpz_init(totient);

	mpz_set_ui(totient, 1);
	
	mpz_sub_ui(temp_1, prime_p, 1);
	mpz_mul(totient, totient, temp_1);

	mpz_sub_ui(temp_1, prime_q, 1);
	mpz_mul(totient, totient, temp_1);

	// Find public exponent that has gcd 1 with totient

	unsigned long int public_exponent = 65537;

	while (mpz_gcd_ui(NULL, totient, public_exponent) != 1 && public_exponent > 0) {
		public_exponent ++;
	}

	log_debug("Public exponent: %lu\n", public_exponent);

	// Calculate the private exponent

	mpz_init(private_exponent);

	mpz_set_ui(totient, public_exponent);

	mpz_invert(private_exponent, temp_1, totient);

	log_debug("Private exponent: %Zd", private_exponent);

	// Calculate the modulus, to put inside the public key file
	mpz_mul(temp_1, prime_p, prime_q);

	write_public_key_to_file(temp_1, public_exponent);
	write_private_key_to_file(prime_p, prime_q, private_exponent);

	mpz_clear(private_exponent);
	mpz_clear(totient);
	mpz_clear(prime_p);
	mpz_clear(prime_q);
	mpz_clear(temp_1);
}

// void encrypt_message(mpz_t message, mpz_t modulus, mpz_t public_exponent);
// void decrypt_message(mpz_t ciphertext, mpz_t modulus, mpz_t
// private_exponent);

int main() {

	// INIT

	int LENGTH_PRIMES_BITS;

	srand(time(NULL));

	// DECIDE BIT LENGTH OF THE PRIMES

	LENGTH_PRIMES_BITS = DEFAULT_PRIME_LENGTH;

	// TODO: Check if the private and public keys exist already
	
	generate_key_pair(LENGTH_PRIMES_BITS);

	printf("\n");
}
