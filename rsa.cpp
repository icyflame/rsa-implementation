#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <stdio.h>
#include "gmp/gmp.h"

#define FILENAME_TEMP_P "temp_p"
#define FILENAME_TEMP_Q "temp_q"

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

int main() {

	// INIT

	int LENGTH_PRIMES_BITS;

	srand(time(NULL));

	// DECIDE BIT LENGTH OF THE PRIMES

	LENGTH_PRIMES_BITS = DEFAULT_PRIME_LENGTH;

	// TODO: Check if the private and public keys exist already

	// Generate random P and Q values
	
	write_random_to_file(FILENAME_TEMP_P, LENGTH_PRIMES_BITS);
	write_random_to_file(FILENAME_TEMP_Q, LENGTH_PRIMES_BITS);

	mpz_t prime_p, prime_q;
	mpz_init(prime_p);
	mpz_init(prime_q);

	mpz_t temp_1;
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

	// Calculate the totient

	mpz_t totient;
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

	printf("Public exponent: %lu\n", public_exponent);

	// Calculate the private exponent

	mpz_t private_exponent;
	mpz_init(private_exponent);

	mpz_set_ui(totient, public_exponent);

	mpz_invert(private_exponent, temp_1, totient);

	gmp_printf("Private exponent: %Zd", private_exponent);

	mpz_clear(private_exponent);
	mpz_clear(totient);
	mpz_clear(prime_p);
	mpz_clear(prime_q);
	mpz_clear(temp_1);

	printf("\n");
}
