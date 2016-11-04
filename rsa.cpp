#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <stdio.h>
#include "gmp/gmp.h"

#define FILENAME_TEMP_P "temp_p"
#define FILENAME_TEMP_Q "temp_q"
#define FILENAME_CIPHERTEXT "ciphertext"

#define FILENAME_PRIVATE_KEY "rsa.private"
#define FILENAME_PUBLIC_KEY "rsa.public"

#define MIN_PUBLIC_EXPONENT 11

#define TIMESTAMP 1
#define DEBUG 1
#define VERBOSE 1
#define log_debug if (DEBUG) gmp_printf
#define log_verbose if (VERBOSE) gmp_printf

void log_timestamp(const char * label) {
	if (!TIMESTAMP) return;
	time_t rawtime;
	struct tm * timeinfo;

	time (&rawtime);
	timeinfo = localtime (&rawtime);
	printf ("%s: %s", label, asctime(timeinfo));
}

#define DEFAULT_PRIME_LENGTH 4

using namespace std;

/**
 * Writes a randomly generated bit_length length binary number
 * to the filename
 */
void write_random_to_file(const char * filename, int bit_length) {
	ofstream fout;
	fout.open(filename, ios::out);
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
		mpz_t &dp, 
		mpz_t &dq, 
		mpz_t &q_inv) {
	FILE * stream;
	stream = fopen(filename, "r");

	gmp_fscanf(stream, "%Zx", p);
	gmp_fscanf(stream, "%Zx", q);
	gmp_fscanf(stream, "%Zx", dp);
	gmp_fscanf(stream, "%Zx", dq);
	gmp_fscanf(stream, "%Zx", q_inv);

	fclose(stream);
}

void write_public_key_to_file(mpz_t modulus, long unsigned int public_exponent) {
	FILE * stream;
	stream = fopen(FILENAME_PUBLIC_KEY, "w");
	
	gmp_fprintf(stream, "%Zx\n%x", modulus, public_exponent);

	fclose(stream);
}

void read_public_key_from_file(const char * filename, mpz_t &modulus, mpz_t &public_exponent) {
	FILE * stream;
	stream = fopen(filename, "r");
	gmp_fscanf(stream, "%Zx", modulus);
	gmp_fscanf(stream, "%Zx", public_exponent);

	fclose(stream);
}

void generate_key_pair(int PRIMES_BIT_LENGTH) {

	mpz_t temp_1, prime_p, prime_q, totient, private_exponent;

	// Generate random P and Q values
	//
	log_timestamp("START Generation random numbers");

	write_random_to_file(FILENAME_TEMP_P, PRIMES_BIT_LENGTH);
	write_random_to_file(FILENAME_TEMP_Q, PRIMES_BIT_LENGTH);

	log_timestamp("END Generation of random numbers");

	mpz_init(prime_p);
	mpz_init(prime_q);

	mpz_init(temp_1);

	// Read the random temp values from the file
	// Find the next smallest prime P and Q
	
	log_timestamp("START Find next prime of random numbers");

	FILE * stream;

	stream = fopen(FILENAME_TEMP_P, "r");
	mpz_inp_str(temp_1, stream, 2);
	fclose(stream);
	mpz_nextprime(prime_p, temp_1);

	stream = fopen(FILENAME_TEMP_Q, "r");
	mpz_inp_str(temp_1, stream, 2);
	fclose(stream);
	mpz_nextprime(prime_q, temp_1);

	log_timestamp("END Find next prime of random numbers");

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
	log_timestamp("START Find a public exponent");

	unsigned long int public_exponent = MIN_PUBLIC_EXPONENT;

	while (mpz_gcd_ui(NULL, totient, public_exponent) != 1 && public_exponent > 0) {
		public_exponent ++;
	}
	log_timestamp("END Find a public exponent");

	log_debug("Public exponent: %lu\n", public_exponent);

	// Calculate the private exponent

	log_timestamp("START Find the private exponent (invert public exponent)");
	mpz_init(private_exponent);

	mpz_set_ui(totient, public_exponent);

	mpz_invert(private_exponent, temp_1, totient);

	log_timestamp("END Find the private exponent (invert public exponent)");
	log_debug("Private exponent: %Zd", private_exponent);

	// Calculate the modulus, to put inside the public key file
	mpz_mul(temp_1, prime_p, prime_q);


	log_timestamp("START Write pub key to file");
	write_public_key_to_file(temp_1, public_exponent);
	log_timestamp("END Write pub key to file");
	log_timestamp("START Write private key to file");
	write_private_key_to_file(prime_p, prime_q, private_exponent);
	log_timestamp("END Write private key to file");

	mpz_clear(private_exponent);
	mpz_clear(totient);
	mpz_clear(prime_p);
	mpz_clear(prime_q);
	mpz_clear(temp_1);
}

void test_encrypt_integer(long unsigned int message, const char * pubkey_filepath, const char * ciphertext_filepath) {
	
	mpz_t modulus, public_exponent, plaintext;
	mpz_init(modulus);
	mpz_init(public_exponent);
	mpz_init(plaintext);

	mpz_set_ui(plaintext, message);

	read_public_key_from_file(pubkey_filepath, modulus, public_exponent);

	log_verbose("Modulus: %Zd\n", modulus);
	log_verbose("Public exponent: %Zd", public_exponent);

	FILE * stream = fopen(ciphertext_filepath, "w");

	// Re-using the same variable to store the ciphertext instead of using a new
	// variable
	mpz_powm(modulus, plaintext, public_exponent, modulus);

	log_verbose("Ciphertext: %Zd", modulus);

	gmp_fprintf(stream, "%Zx", modulus);

	fclose(stream);

	mpz_clear(modulus);
	mpz_clear(public_exponent);
	mpz_clear(plaintext);
}

void test_decrypt_integer(const char * ciphertext_filepath, const char * private_key_filepath) {

	mpz_t p, q, dp, dq, q_inv;
	mpz_init(p);
	mpz_init(q);
	mpz_init(dp);
	mpz_init(dq);
	mpz_init(q_inv);

	// Read the private key from the file
	read_private_key_from_file(private_key_filepath, p, q, dp, dq, q_inv);

	// Read the ciphertext's integer representation
	mpz_t ciphertext_integer_rep;
	mpz_init(ciphertext_integer_rep);
	FILE * stream = fopen(ciphertext_filepath, "r");
	gmp_fscanf(stream, "%Zx", ciphertext_integer_rep);
	fclose(stream);

	// Start the decryption process
	// As per RSADP: 5.1.2 on RFC 3447
	log_timestamp("START Decryption according to RFC");
	
	mpz_t temp_1, temp_2;
	mpz_init(temp_1);
	mpz_init(temp_2);

	mpz_powm(temp_1, ciphertext_integer_rep, dp, p);
	mpz_powm(temp_2, ciphertext_integer_rep, dq, q);

	mpz_sub(temp_1, temp_1, temp_2);
	mpz_mul(temp_1, temp_1, q_inv);

	mpz_mod(temp_1, temp_1, p);

	// Now, temp_1 consists h
	
	mpz_mul(temp_1, temp_1, q);
	
	mpz_t plaintext;
	mpz_init(plaintext);

	mpz_add(plaintext, temp_2, temp_1);

	mpz_t modulus;
	mpz_init(modulus);
	mpz_mul(modulus, p, q);
	mpz_mod(plaintext, plaintext, modulus);

	gmp_printf("That CT decrypts to: %Zd\n", plaintext);

	log_timestamp("END Decryption according to RFC");

	mpz_init(p);
	mpz_init(q);
	mpz_init(dp);
	mpz_init(dq);
	mpz_init(q_inv);
	mpz_init(ciphertext_integer_rep);
	mpz_init(temp_1);
	mpz_init(temp_2);
	mpz_init(plaintext);
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

	log_timestamp("Starting the generation of the keypair");

	// generate_key_pair(LENGTH_PRIMES_BITS);
	
	// test_encrypt_integer(4, FILENAME_PUBLIC_KEY, FILENAME_CIPHERTEXT);

	test_decrypt_integer(FILENAME_CIPHERTEXT, FILENAME_PRIVATE_KEY);

	printf("\n");
}
