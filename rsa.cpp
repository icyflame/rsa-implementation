#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <stdio.h>
#include <libgen.h>
#include <sys/stat.h>
#include <string.h>
#include "gmp/gmp.h"

#define OPTION_HELP_1 "--help"
#define OPTION_HELP_2 "help"
#define OPTION_GENERATE_1 "generate"
#define OPTION_GENERATE_2 "keygen"
#define OPTION_ENCRYPT "encrypt"
#define OPTION_DECRYPT "decrypt"
#define OPTION_CONVERT_INT_TO_STRING "int2string"
#define OPTION_CONVERT_STRING_TO_INT "string2int"

#define ARGS_BITLENGTH "-b"
#define ARGS_FILENAME "-f"
#define ARGS_KEY "-k"

#define FILENAME_TEMP_P "temp_p"
#define FILENAME_TEMP_Q "temp_q"
#define FILENAME_CIPHERTEXT "ciphertext"

#define FILENAME_ENCRYPTED_FILE_SUFFIX ".encrypted"

#define FILENAME_PRIVATE_KEY "rsa.private"
#define FILENAME_PUBLIC_KEY "rsa.public"

#define MIN_PUBLIC_EXPONENT 65537

#define DEFAULT_PRIME_LENGTH 64
#define DEFAULT_FILENAME "rsa"

#define INFO 1
#define TIMESTAMP 1
#define DEBUG 1
#define VERBOSE 0
#define log_debug if (DEBUG) printf("\n"); gmp_printf
#define log_info if (INFO) printf("\n"); printf
#define log_verbose if (VERBOSE) printf("\n"); gmp_printf

/////////////////////////////////////////////
// HELPER FUNCTIONS
////////////////////////////////////////////

void log_timestamp(const char * label) {
	if (!TIMESTAMP) return;
	time_t rawtime;
	struct tm * timeinfo;

	time (&rawtime);
	timeinfo = localtime (&rawtime);
	printf ("\n%s: %s", label, asctime(timeinfo));
}

inline bool file_exists (const std::string& name) {
	struct stat buffer;
	return (stat (name.c_str(), &buffer) == 0); 
}


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
void write_private_key_to_file(mpz_t &p, mpz_t &q, mpz_t &private_exponent, const char * filename) {
	FILE * stream;
	char * priv_key_filename = new char[strlen(filename)];
	strcpy(priv_key_filename, filename);
	strcat(priv_key_filename, ".private");
	stream = fopen(priv_key_filename, "w");

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
	free(priv_key_filename);

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

void write_public_key_to_file(mpz_t modulus, long unsigned int public_exponent, const char * filename) {
	FILE * stream;
	char * pub_key_filename = new char[strlen(filename)];
	strcpy(pub_key_filename, filename);
	strcat(pub_key_filename, ".public");
	stream = fopen(pub_key_filename, "w");
	
	gmp_fprintf(stream, "%Zx\n%x", modulus, public_exponent);

	free(pub_key_filename);
	fclose(stream);
}

void read_public_key_from_file(const char * filename, mpz_t &modulus, mpz_t &public_exponent) {
	FILE * stream;
	stream = fopen(filename, "r");
	gmp_fscanf(stream, "%Zx", modulus);
	gmp_fscanf(stream, "%Zx", public_exponent);

	fclose(stream);
}

void generate_key_pair(int PRIMES_BIT_LENGTH, const char * filename) {

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

	while (mpz_cmp(prime_p, prime_q) == 0) {
		mpz_nextprime(prime_q, prime_q);
	}

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

	log_verbose("Public exponent: %lu\n", public_exponent);

	// Calculate the private exponent

	log_timestamp("START Find the private exponent (invert public exponent)");
	mpz_init(private_exponent);

	mpz_set_ui(temp_1, public_exponent);

	mpz_invert(private_exponent, temp_1, totient);

	log_timestamp("END Find the private exponent (invert public exponent)");
	log_verbose("Private exponent: %Zd", private_exponent);

	// Calculate the modulus, to put inside the public key file
	mpz_mul(temp_1, prime_p, prime_q);


	log_timestamp("START Write pub key to file");
	write_public_key_to_file(temp_1, public_exponent, filename);
	log_timestamp("END Write pub key to file");
	log_timestamp("START Write private key to file");
	write_private_key_to_file(prime_p, prime_q, private_exponent, filename);
	log_timestamp("END Write private key to file");

	mpz_clear(private_exponent);
	mpz_clear(totient);
	mpz_clear(prime_p);
	mpz_clear(prime_q);
	mpz_clear(temp_1);
}

void encrypt_integer_rsa(mpz_t &plaintext, const char * pubkey_filepath, const char * ciphertext_filepath, const char * file_open_mode) {
	
	mpz_t modulus, public_exponent, temp1;
	mpz_init(modulus);
	mpz_init(public_exponent);
	mpz_init(temp1);

	read_public_key_from_file(pubkey_filepath, modulus, public_exponent);

	log_verbose("Writing encrypted content to %s", ciphertext_filepath);
	log_verbose("Modulus: %Zd\n", modulus);
	log_verbose("Public exponent: %Zd", public_exponent);

	// REMEMBER: Encrypted number should ALWAYS be less than the modulus!

	FILE * stream = fopen(ciphertext_filepath, file_open_mode);
	log_verbose("Ciphertext: %Zd", modulus);

	do {
		mpz_fdiv_qr(plaintext, temp1, plaintext, modulus);
		log_debug("PT Chunk: %Zd", temp1);
		// Re-using the same variable to store the ciphertext instead of using a new
		// variable
		mpz_powm(temp1, temp1, public_exponent, modulus);

		log_debug("CT Chunk: %Zd", temp1);

		gmp_fprintf(stream, "%Zx\n", temp1);
	} while (mpz_cmp_ui(plaintext, 0) > 0);


	fclose(stream);

	mpz_clear(temp1);
	mpz_clear(modulus);
	mpz_clear(public_exponent);
	mpz_clear(plaintext);
}

void encrypt_integer_rsa(mpz_t &plaintext, const char * pubkey_filepath, const char * ciphertext_filepath) {
	encrypt_integer_rsa(plaintext, pubkey_filepath, ciphertext_filepath, "w");
}

void decrypt_integer_rsa(const char * ciphertext_filepath, 
													const char * private_key_filepath, 
													mpz_t &plaintext, 
													unsigned long int &octet_len) {

	mpz_t p, q, dp, dq, q_inv;
	mpz_init(p);
	mpz_init(q);
	mpz_init(dp);
	mpz_init(dq);
	mpz_init(q_inv);

	// Read the private key from the file
	read_private_key_from_file(private_key_filepath, p, q, dp, dq, q_inv);

	log_verbose("P: %Zd\nQ: %Zd\ndp: %Zd\ndq: %Zd\nQ_inv: %Zd", p, q, dp, dq, q_inv);

	mpz_t modulus;
	mpz_init(modulus);
	mpz_mul(modulus, p, q);
	mpz_t temp_1, temp_2, intermediary_pt;
	mpz_init(temp_1);
	mpz_init(temp_2);
	mpz_init(intermediary_pt);

	// Read the ciphertext's integer representation
	mpz_t ciphertext_integer_rep;
	mpz_init(ciphertext_integer_rep);
	FILE * stream = fopen(ciphertext_filepath, "r");
	gmp_fscanf(stream, "%x", &octet_len);
	log_verbose("Octet length: %d", octet_len);

	mpz_set_ui(plaintext, 0);
	unsigned long int i = 0;

	while(!feof(stream)) {
		gmp_fscanf(stream, "%Zx", ciphertext_integer_rep);
		log_debug("CT chunk %d: %Zd", i, ciphertext_integer_rep);

		// Start the decryption process
		// As per RSADP: 5.1.2 on RFC 3447
		log_timestamp("START Decryption of chunk according to RFC");

		mpz_powm(temp_1, ciphertext_integer_rep, dp, p);
		mpz_powm(temp_2, ciphertext_integer_rep, dq, q);

		mpz_sub(temp_1, temp_1, temp_2);
		mpz_mul(temp_1, temp_1, q_inv);

		mpz_mod(temp_1, temp_1, p);

		// Now, temp_1 consists h
		
		mpz_mul(temp_1, temp_1, q);

		mpz_add(intermediary_pt, temp_2, temp_1);

		mpz_mod(intermediary_pt, intermediary_pt, modulus);

		log_debug("PT Chunk: %Zd", intermediary_pt);

		if (i == 0) {
			mpz_add(plaintext, plaintext, intermediary_pt);
		} else {
			mpz_pow_ui(temp_1, modulus, i);
			mpz_mul(temp_1, temp_1, intermediary_pt);
			mpz_add(plaintext, plaintext, temp_1);
		}
		++i;
	}

	fclose(stream);

	log_verbose("That CT decrypts to: %Zd\n", plaintext);

	log_timestamp("END Decryption according to RFC");

	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(dp);
	mpz_clear(dq);
	mpz_clear(q_inv);
	mpz_clear(ciphertext_integer_rep);
	mpz_clear(temp_1);
	mpz_clear(temp_2);
	mpz_clear(intermediary_pt);
}

void printHelp() {
	printf("\n----------------------------------");
	printf("\nRSA Implementation - Using GNU GMP\n\n");
	printf("\nrsa keygen -b 512 -f filename");
	printf("\nrsa generate -b 512 -f filename");
	printf("\nrsa encrypt -f filename -key siddharth.pub");
	printf("\nrsa decrypt -f ciphertext -key my.private.key");
	printf("\nTESTING OPTIONS");
	printf("\nrsa int2string 7881696744884301945 8");
	printf("\nrsa convert string2int \"main2.py\"");
	printf("\n----------------------------------");
}

void convert_string_to_integer(const char * plaintext, mpz_t &string_representation, mpz_t &octet_len) {
	// Find the string size
	unsigned long int lSize = strlen(plaintext);
	mpz_set_ui(octet_len, lSize);

	mpz_set_ui(string_representation, 0);

	mpz_t temp;
	mpz_init(temp);
	
	for(int i = 0; i < lSize; ++i) {
		char this_char = plaintext[i];
		mpz_ui_pow_ui(temp, 256, lSize - i - 1);
		mpz_mul_ui(temp, temp, this_char);
		mpz_add(string_representation, string_representation, temp);
	}

	// log_verbose("\nInteger repesentation of %s is: %Zd\nwith octet length of %Zd", plaintext, string_representation, octet_len);

	mpz_clear(temp);
}

void convert_file_to_integer(const char * filepath, mpz_t &file_representation, mpz_t &octet_len) {
	if (!file_exists(string(filepath))) {
		return;
	}
	FILE * stream = fopen(filepath, "rb");
	char * values;

	// Find the file size
	fseek (stream, 0, SEEK_END);
	unsigned long int lSize = ftell (stream);
	rewind (stream);

	values = new char[lSize * sizeof(char)];
	size_t result = fread(values, 1, lSize, stream);

	if (result != lSize) {
		printf("ERROR! File couldn't be converted to it's integer representation.");
		return;
	}

	mpz_set_ui(file_representation, 0);
	mpz_set_ui(octet_len, lSize);

	mpz_t temp;
	mpz_init(temp);
	
	for(int i = 0; i < lSize; ++i) {
		char this_char = values[i];
		mpz_ui_pow_ui(temp, 256, lSize - i - 1);
		mpz_mul_ui(temp, temp, this_char);
		mpz_add(file_representation, file_representation, temp);
	}

	// log_verbose("\nInteger repesentation of that file is: %Zd\nwith octet length of %Zd", file_representation, octet_len);

	mpz_clear(temp);
	fclose(stream);
}

char * convert_integer_to_string(mpz_t &int_rep, unsigned long int octet_len) {
	char * string_rep = new char[(octet_len+1) * sizeof(char)];

	log_timestamp("START Converting the given integer to it's octet string representation");

	mpz_t divisor, remainder;
	mpz_init(divisor);
	mpz_init(remainder);

	mpz_set(divisor, int_rep);

	mpz_t OCTET_BASE;
	mpz_init(OCTET_BASE);
	mpz_set_ui(OCTET_BASE, 256);

	string_rep[octet_len] = '\0';
	--octet_len;
	
	while(mpz_cmp_ui(int_rep, 0) > 0 && octet_len >= 0) {
		string_rep[octet_len--] = (char) mpz_fdiv_qr_ui(int_rep, remainder, int_rep, 256);
		// log_verbose("Integer representation of this character: %u, %c; Remainder: %Zd", string_rep[octet_len+1], string_rep[octet_len+1], remainder);
	}

	log_verbose("Integer rep now: %Zd", int_rep);
	log_verbose("Octet length now: %d", octet_len);

	log_verbose("\nGiven integer represents the string %s", string_rep);

	mpz_clear(divisor);
	mpz_clear(remainder);
	
	return string_rep;
}

char * convert_integer_to_string(unsigned long int int_rep, unsigned long int octet_len) {
	mpz_t int_rep_gmp;
	mpz_init(int_rep_gmp);
	mpz_set_ui(int_rep_gmp, int_rep);
	char * result = convert_integer_to_string(int_rep_gmp, octet_len);
	mpz_clear(int_rep_gmp);
	return result;
}

void convert_integer_to_file(mpz_t &int_rep, unsigned long int octet_len, const char * output_filename) {
	FILE * stream = fopen(output_filename, "w");
	char * string_rep = convert_integer_to_string(int_rep, octet_len);
	fprintf(stream, "%s", string_rep);
	free(string_rep);
	fclose(stream);
}
	

//void convert_integer_to_file(mpz_t &file_representation, mpz_t &filename_representation) {
//}

// void encrypt_message(mpz_t message, mpz_t modulus, mpz_t public_exponent);
// void decrypt_message(mpz_t ciphertext, mpz_t modulus, mpz_t
// private_exponent);

int main(int argc, char **ARGV) {

	// INIT

	int LENGTH_PRIMES_BITS;

	srand(time(NULL));

	// DECIDE BIT LENGTH OF THE PRIMES

	LENGTH_PRIMES_BITS = DEFAULT_PRIME_LENGTH;

	// Command line argument parsing
	int matched = 0;
	
	if (argc == 1) {
		printf("ERROR! You must use one of the available options.");
		printHelp();
		return 1;
	}

	if (strcmp(ARGV[1], OPTION_HELP_1) == 0 || strcmp(ARGV[1], OPTION_HELP_2) == 0) {
		matched = 1;
		printHelp();
	}

	if (strcmp(ARGV[1], OPTION_GENERATE_1) == 0 || strcmp(ARGV[1], OPTION_GENERATE_2) == 0) {
		matched = 1;
		printf("\nWe will generate a set of keys now");
		int bitlength = DEFAULT_PRIME_LENGTH;

		char * keys_filename= new char[strlen(DEFAULT_FILENAME)];
		strcpy(keys_filename, DEFAULT_FILENAME);

		if (argc == 4 || argc == 6) {
			// More options may have been passed
			if (strcmp(ARGV[2], ARGS_BITLENGTH) == 0) {
				bitlength = atoi(ARGV[3]);
			}

			if (strcmp(ARGV[2], ARGS_FILENAME) == 0) {
				free(keys_filename);
				keys_filename = new char[strlen(ARGV[3])];
				strcpy(keys_filename, ARGV[3]);
			}

			if (argc == 6) {
				if (strcmp(ARGV[4], ARGS_FILENAME) == 0) {
					free(keys_filename);
					keys_filename = new char[strlen(ARGV[5])];
					strcpy(keys_filename, ARGV[5]);
				}

				if (strcmp(ARGV[4], ARGS_BITLENGTH) == 0) {
					bitlength = atoi(ARGV[5]);
				}
			}
		}
		log_info("\nGenerating keys with prime bitlength %d and name %s", bitlength, keys_filename);
		generate_key_pair(bitlength, keys_filename);
	}

	if (strcmp(ARGV[1], OPTION_ENCRYPT) == 0) {
		if (argc == 4 || argc == 6) {
			matched = 1;
			// Check that atleast one option is the file to encrypt
			if (strcmp(ARGV[2], ARGS_FILENAME) != 0 && (argc > 4 ? strcmp(ARGV[4], ARGS_FILENAME) != 0 : 0)) {
				matched = 0;
			} else {
				printf("\nWe can try to encrypt the file now");
				char * pubkey_filename = new char[strlen(DEFAULT_FILENAME)];
				strcpy(pubkey_filename, DEFAULT_FILENAME);
				strcat(pubkey_filename, ".public");
				char * plaintext;
				if (strcmp(ARGV[2], ARGS_FILENAME) == 0) {
					plaintext = new char[strlen(ARGV[3])];
					strcpy(plaintext, ARGV[3]);
				}

				if (strcmp(ARGV[2], ARGS_KEY) == 0) {
					free(pubkey_filename);
					pubkey_filename = new char[strlen(ARGV[3])];
					strcpy(pubkey_filename, ARGV[3]);
				}

				if (argc == 6) {
					if (strcmp(ARGV[4], ARGS_FILENAME) == 0) {
						plaintext = new char[strlen(ARGV[5])];
						strcpy(plaintext, ARGV[5]);
					}

					if (strcmp(ARGV[4], ARGS_KEY) == 0) {
						free(pubkey_filename);
						pubkey_filename = new char[strlen(ARGV[5])];
						strcpy(pubkey_filename, ARGV[5]);
					}
				}

				if (!file_exists(string(plaintext))) {
					printf("\nERROR! Plaintext file %s doesn't exist!\n", plaintext);
					return 1;
				}
				if (!file_exists(string(pubkey_filename))) {
					printf("\nERROR! Public key file %s doesn't exist!\n", pubkey_filename);
					return 1;
				}
				log_info("\nEncryption the file %s using the public key %s", plaintext, pubkey_filename);
				// TODO: Hook up the function that will directly encrypt the given
				// filepath
				// Get the integer representation of the file
				mpz_t file_rep, octet_len;
				mpz_init(file_rep);
				mpz_init(octet_len);
				convert_file_to_integer(plaintext, file_rep, octet_len);
				
				// Get the filename of the ciphertext
				char * filename_base = basename(plaintext);
				char * ciphertext_filename = new char[strlen(filename_base) + strlen(FILENAME_ENCRYPTED_FILE_SUFFIX)];
				strcat(ciphertext_filename, filename_base);
				strcat(ciphertext_filename, FILENAME_ENCRYPTED_FILE_SUFFIX);
				
				// Write the octet len of the integer to the file
				FILE * stream = fopen(ciphertext_filename, "w");
				gmp_fprintf(stream, "%Zx\n", octet_len);
				fclose(stream);
				
				// Now, write the ciphertext to the file
				// Append it to this file, instead of writing it to a new file
				// While reading, read with gmp_fscanf(stream, "%Zx\n%Zx", octet_len, ciphertext_int_rep);
				encrypt_integer_rsa(file_rep, pubkey_filename, ciphertext_filename, "a");
			}
		}
	}

	if (strcmp(ARGV[1], OPTION_DECRYPT) == 0) {
		if (argc == 4 || argc == 6) {
			matched = 1;
			// Check that atleast one option is the file to decrypt
			if (strcmp(ARGV[2], ARGS_FILENAME) != 0 && (argc > 4 ? strcmp(ARGV[4], ARGS_FILENAME) != 0 : 0)) {
				matched = 0;
			} else {
				printf("\nWe can try to decrypt the file now");
				char * priv_key_filename = new char[strlen(DEFAULT_FILENAME)];
				strcpy(priv_key_filename, DEFAULT_FILENAME);
				strcat(priv_key_filename, ".private");
				char * ciphertext;
				if (strcmp(ARGV[2], ARGS_FILENAME) == 0) {
					ciphertext = new char[strlen(ARGV[3])];
					strcpy(ciphertext, ARGV[3]);
				}

				if (strcmp(ARGV[2], ARGS_KEY) == 0) {
					free(priv_key_filename);
					priv_key_filename = new char[strlen(ARGV[3])];
					strcpy(priv_key_filename, ARGV[3]);
				}

				if (argc == 6) {
					if (strcmp(ARGV[4], ARGS_FILENAME) == 0) {
						ciphertext = new char[strlen(ARGV[5])];
						strcpy(ciphertext, ARGV[5]);
					}

					if (strcmp(ARGV[4], ARGS_KEY) == 0) {
						free(priv_key_filename);
						priv_key_filename = new char[strlen(ARGV[5])];
						strcpy(priv_key_filename, ARGV[5]);
					}
				}

				if (!file_exists(string(ciphertext))) {
					printf("\nERROR! Ciphertext file %s doesn't exist!\n", ciphertext);
					return 1;
				}
				if (!file_exists(string(priv_key_filename))) {
					printf("\nERROR! Private key file %s doesn't exist!\n", priv_key_filename);
					return 1;
				}
				log_info("\nDecrypting the file %s using the private key %s", ciphertext, priv_key_filename);
				// TODO: Hook up the function that will decrypt the given
				// filepath
				
				// Decrypt the file to get the plaintext integer representation and the
				// octet length of the plaintext itself
				mpz_t plaintext;
				mpz_init(plaintext);
				unsigned long int octet_len = 0;
				decrypt_integer_rsa(ciphertext, priv_key_filename, plaintext, octet_len);

				// Now, find the name of the plaintext file
				// before encryption
				string plaintext_filename = string(ciphertext).substr(0, strlen(ciphertext) - strlen(FILENAME_ENCRYPTED_FILE_SUFFIX));
				
				convert_integer_to_file(plaintext, octet_len, plaintext_filename.c_str());
			}
		}
	}

	if (strcmp(ARGV[1], OPTION_CONVERT_INT_TO_STRING) == 0 && argc == 4) {
		matched = 1;
		char * end;
		mpz_t int_rep;
		mpz_init(int_rep);
		gmp_sscanf(ARGV[2], "%Zd", int_rep);
		unsigned long int octet_len = atoi(ARGV[3]);
		convert_integer_to_string(int_rep, octet_len);
		mpz_clear(int_rep);
	}

	if (strcmp(ARGV[1], OPTION_CONVERT_STRING_TO_INT) == 0 && argc == 3) {
		matched = 1;
		mpz_t rep, octet_len;
		mpz_init(rep);
		mpz_init(octet_len);
		convert_string_to_integer(ARGV[2], rep, octet_len);
		mpz_clear(rep);
		mpz_clear(octet_len);
	}

	if (!matched) {
		printf("\nERROR! Invalid option. Run `rsa --help` for help text\n");
		return 1;
	}

	printf("\n");

	return 0;

}
