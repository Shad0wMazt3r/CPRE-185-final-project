#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>

/*
Prototypes
*/
void print_banner();
void print_menu();
void handle_input();
int switch_fn(char user_input);
void bruteforce();
int is_valid_base32(const char* input);
int is_valid_base64(const char* input);
void vignere_cipher();
void b64();
void encode_b64(char* input);
void decode_b64(char* input);
void b32();
void encode_b32(char* input);
void decode_b32(char* input);
void ceasers_cipher();
void decode_ceasers(int shift, char* input);
void help_box();
void extended_help();

/*
Main Function

Contains the variable declarations and input loop
*/

int main()
{
	printf("Welcome to the Cipher Solver!\n");
	int exit = 0;
	while(exit == 0)
	{
		print_menu();
		handle_input();
	}
	return 0;
}
/*
Prints banner for selection screen
*/
void print_menu()
{
	printf("-------------------------------------------\n");
	printf("Please make a selection from the menu:\n");
	printf("1. Automatic bruteforce for encodings\n");
	printf("2. Ceaser's Cipher\n");
	printf("3. Vignere Cipher\n");
	printf("4. Base64 Decode\n");
	printf("5. Base32 Decode\n");
	printf("Enter h for help.\n");
	printf("-------------------------------------------\n");
}
/*
Bruteforces the input string
*/
void bruteforce()
{
	char input[500];
	printf("Please enter the string: ");
	scanf(" %[^\n]s", input);
	printf("Bruteforcing %s\n", input);
	// regex to check if the input is a valid base64 string
	if (is_valid_base64(input))
	{
		decode_b64(input);
	}
	else if (is_valid_base32(input))
	{
		decode_b32(input);
	}
	else
	{
		printf("The input is not a valid base64 or base32 string.\n");
		printf("Trying Ceaser's Cipher...\n");
		printf("If this is not the correct string, try vignere cipher manually.\n");
		decode_ceasers(13, input);
	}
}
/*
Regex to check if the input is a valid base64 string
*/
int is_valid_base64(const char* input) {
	regex_t regex;
	int reti;

	// Compile the regular expression
	reti = regcomp(&regex, "^[A-Za-z0-9+/]*={0,2}$", REG_EXTENDED);
	if (reti) {
		fprintf(stderr, "Could not compile regex\n");
		return 0;
	}

	// Execute the regular expression
	reti = regexec(&regex, input, 0, NULL, 0);
	regfree(&regex);

	if (!reti) {
		// Match found, input is a valid base64 string
		return 1;
	} else if (reti == REG_NOMATCH) {
		// No match found, input is not a valid base64 string
		return 0;
	} else {
		// Error occurred while executing the regular expression
		fprintf(stderr, "Regex match failed\n");
		return 0;
	}
}
/*
Regex to check if the input is a valid base32 string
*/
int is_valid_base32(const char* input) {
	regex_t regex;
	int reti;
	// Compile the regular expression
	reti = regc	omp(&regex, "^[A-Z2-7]*={0,6}$", REG_EXTENDED);
	if (reti) {
		// Error compiling the regular expression
		fprintf(stderr, "Could not compile regex\n");
		return 0;
	}
	// Execute the regular expression
	reti = regexec(&regex, input, 0, NULL, 0);
	regfree(&regex);
	if (!reti) {
		// Match found, input is a valid base32 string
		return 1;
	} else if (reti == REG_NOMATCH) {
		// No match found, input is not a valid base32 string
		return 0;
	} else {
		// Error executing the regular expression
		fprintf(stderr, "Regex match failed\n");
		return 0;
	}
}
/*
Vignere Cipher
Uses a key to encode/decode a string
*/

void vignere_cipher() {
    char input[500];
    printf("Please enter the string to decode: ");
    scanf(" %[^\n]s", input);
    
    char key[500];
    printf("Please enter the key: ");
    scanf("%s", key);

    int key_length = strlen(key);
    int input_length = strlen(input);

    char output[input_length + 1];
    output[input_length] = '\0';

    for (int i = 0, j = 0; i < input_length; i++) {
        if (j == key_length) {
            j = 0;  // Reset key index when it reaches the key length
        }

        char current_char = input[i];
        char key_char = key[j];
        int shift = 0;

        // Calculate the shift based on the key
        if (key_char >= 'a' && key_char <= 'z') {
            shift = key_char - 'a';
        } else if (key_char >= 'A' && key_char <= 'Z') {
            shift = key_char - 'A';
        }

        // Apply backward shift for decoding
        if (current_char >= 'a' && current_char <= 'z') {
            current_char = 'a' + (current_char - 'a' - shift + 26) % 26;
        } else if (current_char >= 'A' && current_char <= 'Z') {
            current_char = 'A' + (current_char - 'A' - shift + 26) % 26;
        }

        output[i] = current_char;  // Store the decoded character
        j++;  // Move to the next key character
    }

    printf("The decoded string is: %s\n", output);  // Output the decoded text
}
/*
Collect input from the user and encode/decode the string using base64
*/
void b64()
{
	char input[500];
	printf("Please enter the string: ");
	scanf(" %[^\n]s", input);
	char decode_or_encode;
	printf("Would you like to decode or encode? [d/e]: ");
	scanf(" %c", &decode_or_encode);

	// Check if the user wants to decode or encode
	if (decode_or_encode == 'd')
	{
		printf("Decoding %s\n", input);
		decode_b64(input);
	}
	else if (decode_or_encode == 'e')
	{
		printf("Encoding %s\n", input);
		encode_b64(input);
	}
	else
	{
		printf("Invalid input. Please try again.\n");
	}
}
/*
Encode the input string using base64
*/
void encode_b64(char* input)
{
	// Base64 encoding table
	char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	int input_length = strlen(input);

	int output_length = ((input_length + 2) / 3) * 4;

	char* output = (char*)malloc(output_length + 1);
	output[output_length] = '\0';

	// Encode the input string
	int i, j;
	for (i = 0, j = 0; i < input_length;)
	{
		// Get the indices of the three characters to be encoded
		unsigned char index1 = input[i++];
		unsigned char index2 = (i < input_length) ? input[i++] : 0;
		unsigned char index3 = (i < input_length) ? input[i++] : 0;

		// Encode the characters and store them in the output string
		output[j++] = encoding_table[index1 >> 2];
		output[j++] = encoding_table[((index1 & 3) << 4) | (index2 >> 4)];
		output[j++] = (index2 != 0) ? encoding_table[((index2 & 15) << 2) | (index3 >> 6)] : '=';
		output[j++] = (index3 != 0) ? encoding_table[index3 & 63] : '=';
	}

	printf("The encoded string is: %s\n", output);

	free(output);
}

/*
Decodes base64 encoded string
*/
void decode_b64(char* input)
{
	// Base64 decoding table
	char decoding_table[256] = {0};
	char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	// Populate the decoding table
	for (int i = 0; i < 64; i++)
	{
		decoding_table[(unsigned char)base64_chars[i]] = i;
	}

	int input_length = strlen(input);

	int output_length = (input_length / 4) * 3;
	if (input[input_length - 1] == '=')
	{
		output_length--;
	}
	if (input[input_length - 2] == '=')
	{
		output_length--;
	}

	char* output = (char*)malloc(output_length + 1);
	output[output_length] = '\0';

	// Decode the input string
	int i, j;
	for (i = 0, j = 0; i < input_length;)
	{
		// Get the indices of the four characters to be decoded
		unsigned char index1 = decoding_table[(unsigned char)input[i++]];
		unsigned char index2 = decoding_table[(unsigned char)input[i++]];
		unsigned char index3 = decoding_table[(unsigned char)input[i++]];
		unsigned char index4 = decoding_table[(unsigned char)input[i++]];

		// Decode the characters and store them in the output string
		output[j++] = (index1 << 2) | (index2 >> 4);
		if (index3 != 64)
		{
			output[j++] = ((index2 & 15) << 4) | (index3 >> 2);
		}
		if (index4 != 64)
		{
			output[j++] = ((index3 & 3) << 6) | index4;
		}
	}

	printf("The decoded string is: %s\n", output);

	free(output);
}
/*
Collect input from the user and encode/decode the string using base32
*/
void b32()
{
	char input[500];
	printf("Please enter the string: ");
	scanf(" %[^\n]s", input);

	char decode_or_encode;
	
	printf("Would you like to decode or encode? [d/e]: ");
	scanf(" %c", &decode_or_encode);
	
	if (decode_or_encode == 'd')
	{
		printf("Decoding %s\n", input);
		decode_b32(input);
	}
	
	else if (decode_or_encode == 'e')
	{
		printf("Encoding %s\n", input);
		encode_b32(input);
	}
	
	else
	{
		printf("Invalid input. Please try again.\n");
	}
}
void encode_b32(char* input) {
    // Base32 character set
    const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    int input_length = strlen(input);

    int output_length = ((input_length * 8) + 4) / 5;  // Minimum Base32 characters
    int padded_length = ((output_length + 7) / 8) * 8;  // Pad to multiple of 8
    char* output = (char*)malloc(padded_length + 1);
    output[padded_length] = '\0';

    int bit_buffer = 0;  // Buffer to accumulate bits
    int bit_count = 0;  // Number of bits in the buffer
    int output_index = 0;  // Index to fill the output array

    // Traverse the input string
    for (int i = 0; i < input_length; i++) {
        // Get the current byte from the input string
        unsigned char byte = (unsigned char)input[i];

        // Add this byte to the bit buffer
        bit_buffer = (bit_buffer << 8) | byte;
        bit_count += 8;

        // Extract Base32 characters as long as we have at least 5 bits in the buffer
        while (bit_count >= 5) {
            bit_count -= 5;
            int index = (bit_buffer >> bit_count) & 0x1F;  // Get top 5 bits
            output[output_index++] = base32_chars[index];
        }
    }

    // Handle any remaining bits in the buffer (less than 5 bits)
    if (bit_count > 0) {
        int index = (bit_buffer << (5 - bit_count)) & 0x1F;  // Pad remaining bits
        output[output_index++] = base32_chars[index];
    }

    // Add padding (`=`) to ensure the output length is a multiple of 8
    while (output_index < padded_length) {
        output[output_index++] = '=';
    }

    printf("Base32-encoded output: %s\n", output);

    free(output);
}
/*
Decode the input string using base32
*/
void decode_b32(char* input)
{
	// Base32 decoding table
	char decoding_table[256] = {0};
	char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

	// Populate the decoding table
	for (int i = 0; i < 32; i++)
	{
		decoding_table[(unsigned char)base32_chars[i]] = i;
	}

	// Calculate the length of the input string
	int input_length = strlen(input);

	// Calculate the length of the output string
	int output_length = (input_length / 8) * 5;
	if (input[input_length - 1] == '=')
	{
		output_length--;
	}
	if (input[input_length - 2] == '=')
	{
		output_length--;
	}

	// Allocate memory for the output string
	char* output = (char*)malloc(output_length + 1);
	output[output_length] = '\0';
  	// Convert Base32 to binary
    int bit_buffer = 0; // To hold bits
    int bit_count = 0; // To count the bits
    int output_index = 0;

    for (int i = 0; i < input_length; i++) {
        if (input[i] == '=') {
            break;
        }

        // Get the value of the Base32 character
        int value = decoding_table[(unsigned char)input[i]];
        if (value == 0 && input[i] != 'A') {
            fprintf(stderr, "Invalid character in Base32 input.\n");
            free(output);
            return;
        }

        // Accumulate the bits
        bit_buffer = (bit_buffer << 5) | value;
        bit_count += 5;

        // When we have 8 or more bits, extract a byte
        if (bit_count >= 8) {
            bit_count -= 8;
            output[output_index++] = (bit_buffer >> bit_count) & 0xFF;
        }
    }

    // Print the decoded output
    printf("Decoded output: ");
    for (int i = 0; i < output_index; i++) {
        printf("%c", output[i]);
    }
    printf("\n");

    free(output);
}
/*
Get user input and decode/encode the string using Ceaser's Cipher
*/
void ceasers_cipher()
{
	char input[500];
	printf("Please enter the string: ");
	scanf(" %[^\n]s", input);
	printf("Enter the shift value [Default: 13]: ");
	int shift;
	scanf("%d", &shift);
	if (shift == 0)
	{
		shift = 13;
	}
	decode_ceasers(shift, input);
}
/*
Decode the input string using Ceaser's Cipher with the given shift value
*/
void decode_ceasers(int shift, char* input)
{
	int i;
	for (i = 0; i < strlen(input); i++)
	{
		if (input[i] >= 'a' && input[i] <= 'z')
		{
			input[i] = input[i] - shift;
			if (input[i] < 'a')
			{
				input[i] = input[i] + 26;
			}
		}
		else if (input[i] >= 'A' && input[i] <= 'Z')
		{
			input[i] = input[i] - shift;
			if (input[i] < 'A')
			{
				input[i] = input[i] + 26;
			}
		}
	}
	printf("The decoded string is: %s\n", input);
	printf("Is this the correct string? [y/n]: ");
	char response;
	scanf(" %c", &response);
	if (response == 'y')
	{
		printf("Great! The string has been decoded.\n");
	}
	else if (response == 'n')
	{
		printf("Here's the other possible strings:\n");
	for (shift = 1; shift < 26; shift++)
	{	
		for (i = 0; i < strlen(input); i++)
		{
			if (input[i] >= 'a' && input[i] <= 'z')
			{
				input[i] = input[i] + shift;
				if (input[i] > 'z')
				{
					input[i] = input[i] - 26;
				}
			}
			else if (input[i] >= 'A' && input[i] <= 'Z')
			{
				input[i] = input[i] + shift;
				if (input[i] > 'Z')
				{
					input[i] = input[i] - 26;
				}
			}
		}
		printf("Shift %d: %s\n", shift, input);
	}
	}
	else
	{
		printf("Invalid input. Please try again.\n");
	}
}

/*
Help menu for the user
*/
void help_box()
{
	printf("Help Menu\n");
	printf("1. Automatic bruteforce for encodings\n");
	printf("- This option will automatically attempt to decode the input string using all possible methods.\n");
	printf("2. Ceaser's Cipher\n");
	printf("- This option will decode the input string using the Ceaser's Cipher method. (also known as ROT13)\n");
	printf("3. Vignere Cipher\n");
	printf("- This option will decode the input string using the Vignere Cipher method.\n");
	printf("4. Base64 Decode\n");
	printf("- This option will decode the input string using the Base64 decoding method.\n");
	printf("5. Base32 Decode\n");
	printf("- This option will decode the input string using the Base32 decoding method.\n");
	printf("\nEnter h for extended help menu, r to go back to main screen or q to quit the program:");
	char input;
	scanf(" %c", &input);
	if (input == 'h')
	{
		extended_help();
	}
	else if (input == 'r')
	{
		return;
	}
	else if (input == 'q')
	{
		exit(0);
	}
	else
	{
		printf("%c: Command not recognized.", input);
		return;
	}
}

/* 
Extended help menu for more information on the options
*/
void extended_help()
{
	printf("Extended Help Menu\n");
	printf("1. Automatic bruteforce for encodings\n");
	printf("- This option will automatically attempt to decode the input string using all possible methods.\n");
	printf("2. Ceaser's Cipher\n");
	printf("-  In cryptography, a Caesar cipher, also known as Caesar's cipher, the shift cipher, Caesar's code or Caesar shift, is one of the simplest and most widely known encryption techniques.\n");
	printf("3. Vignere Cipher\n");
	printf("- The Vigenère cipher is a method of encrypting alphabetic text by using a simple form of polyalphabetic substitution.\n");
	printf("4. Base64 Decode\n");
	printf("- Base64 is a group of binary-to-text encoding schemes that represent binary data in an ASCII string format by translating it into a radix-64 representation.\n");
	printf("5. Base32 Decode\n");
	printf("- Base32 is a base-32 encoding scheme that uses a 32-character set consisting of the letters A-Z and the digits 2-7.\n");
}
/* Get user input and pass it to switch_fn */
void handle_input()
{
	char user_input;
	int switch_res;
	printf("Please enter your choice:");
	scanf(" %c", &user_input);	
	switch_res = switch_fn(user_input);
}

/*
Switch case function to handle user input
*/
int switch_fn(char user_input)
{
	switch(user_input)
	{
		case 'h':
			help_box();
			break;
		case '1':
			bruteforce();
			break;
		case '2':
			ceasers_cipher();
			break;
		case '3':
			vignere_cipher();
			break;
		case '4':
			b64();
			break;
		case '5':
			b32();
			break;
		default:
        	printf("Invalid input, please try again.\n");
        break;
	}
	return 0;
}
