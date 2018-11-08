#include <3ds.h>
#include <cstring>
#include <cstdio>
#include "crypto.h"

typedef uint32_t element[8];
void ninty_233_ecdsa_sign_sha256(uint8_t * input, int length, const uint8_t * private_key, element r_out, element s_out);
void elem_to_os(const element src, uint8_t * output_os);

void getSection(u8 *dsiware_pointer, u32 section_size, u8 *key, u8 *output) {
        decryptAES(dsiware_pointer, section_size, key, (dsiware_pointer + section_size + 0x10), output);
}

void placeSection(u8 *dsiware_pointer, u8 *section, u32 section_size, u8 *key, u8 *key_cmac) {
        u8 allzero[0x10]= {0};

        encryptAES(section, section_size, key, allzero, dsiware_pointer);

        u8 section_hash[0x20];
        calculateSha256(section, section_size, section_hash);
        u8 section_cmac[0x20];
        calculateCMAC(section_hash, 0x20, key_cmac, section_cmac);

        memcpy((dsiware_pointer + section_size), section_cmac, 0x10);
        memset((dsiware_pointer + section_size + 0x10), 0, 0x10);
}

/*

1) Read in the Public/Private key pair from the ctcert.bin into the KeyPair object
2) Copy the ctcert.bin to the CTCert section of the footer.bin
3) Take the 13 hashes at the top, and hash them all to get a single master hash of all the contents of the DSiWare container
4) Sign that hash. Retrieve the ECDSA (X, Y) coordinates in the form of byte arrays, each one of size 0x1E.
   If the points retrieved are not 0x1E in size, add padding 0s at the start. Then, take those two arrays,
   combine them and you'll get a single big byte array of size 0x3C. Place that in the correct spot for the footer. (it's placed
   immediately after the 13 hashes, i.e. 13 * 0x20 == 0x1A0)

5) Make a new byte array of size 0x40. Then, fill it up with this formula:
    snprintf(your_byte_array, 0x40, "%s-%s", ctcert->issuer, ctcert->key_id);
6) Copy that byte array into the issuer section for the APCert (it's at offset 0x80 relative to the start of the APCert)
7) Hash the APCert's bytes in the range of 0x80 to 0x180 (in total 0x100 bytes).
   Essentially skip the signature portion of the APCert (cause you don't sign a signature)
8) Sign that hash you just created with your KeyPair. Do the same coordinate retrieval process as for step 4.
9) Take your coordinates byte array (2 * 0x1E = 0x3C in size), and place it in the signature
   section of the APCert (it's at offset 0x04 relative to the start of the APCert)
10) Copy the public key byte array into the APCert's public key field (it's at offset 0x108 relative to the start of the APCert)

*/