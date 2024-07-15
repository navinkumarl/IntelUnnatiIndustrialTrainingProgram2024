#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "crypto_wrapper.h"

#include <cstring>
#include <iostream> // for error messages
#include <cstdio>

#ifdef OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>

#include <openssl/applink.c>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/dh.h>


#ifdef WIN
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "openssl.lib")
#endif // #ifdef WIN

static constexpr size_t PEM_BUFFER_SIZE_BYTES	= 10000;
static constexpr size_t HASH_SIZE_BYTES			= 32; //To be define by the participants - SHA-256 hash size in bytes
static constexpr size_t IV_SIZE_BYTES			= 12; //To be define by the participants - AES-GCM standard IV size
static constexpr size_t GMAC_SIZE_BYTES			= 16; //To be define by the participants - AES-GCM standard GMAC size


bool CryptoWrapper::hmac_SHA256(const BYTE* key, size_t keySizeBytes, const BYTE* message,
	size_t messageSizeBytes, BYTE* macBuffer, size_t macBufferSizeBytes)
{
	// Define the SHA-256 Digest Algorithm
	const EVP_MD* md = EVP_sha256();

	// Calculate the HMAC using the Provided Key, Message, and SHA-256 Digest Algorithm
	unsigned int mdLen;
	unsigned char* result = HMAC(md, key, static_cast<int>(keySizeBytes), message, messageSizeBytes, macBuffer, &mdLen);

	if (result == nullptr) {
		std::cerr << "Error: HMAC Computation Failed." << std::endl; // Handle Error: HMAC Computation Failed
		goto err;
	}

	if (mdLen != macBufferSizeBytes) {
		std::cerr << "Error: Invalid MAC Size." << std::endl; // Handle Error: Invalid MAC Size
		goto err;
	}

	return true;

err:
	// Clean Up or Handle Errors Here
	return false;
}

/*
bool CryptoWrapper::hmac_SHA256(IN const BYTE* key, size_t keySizeBytes, IN const BYTE* message, IN size_t messageSizeBytes, OUT BYTE* macBuffer, IN size_t macBufferSizeBytes)
{
	EVP_MD_CTX* ctx = NULL;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	{
		goto err;
	}


err:
	EVP_MD_CTX_free(ctx);

	return false;

	// ...
}
*/

bool CryptoWrapper::deriveKey_HKDF_SHA256(const BYTE* salt, size_t saltSizeBytes, const BYTE* secretMaterial,
	size_t secretMaterialSizeBytes, const BYTE* context, size_t contextSizeBytes,
	BYTE* outputBuffer, size_t outputBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY_CTX* pctx = NULL;
	size_t outlen = outputBufferSizeBytes;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pctx == NULL) {
		std::cerr << "Error: Failed to Create HKDF Context." << std::endl; // Handle Error: Creating HKDF Context
		goto err;
	}

	if (EVP_PKEY_derive_init(pctx) <= 0) {
		std::cerr << "Error: Failed to Initialize HKDF Derivation." << std::endl; // Handle Error: Initializing HKDF Derivation
		goto err;
	}

	if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
		std::cerr << "Error: Failed to Set HKDF Hash Function." << std::endl; // Handle Error: Setting HKDF Hash Function
		goto err;
	}

	if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltSizeBytes) <= 0) {
		std::cerr << "Error: Failed to Set HKDF Salt." << std::endl; // Handle Error: Setting HKDF Salt
		goto err;
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secretMaterial, secretMaterialSizeBytes) <= 0) {
		std::cerr << "Error: Failed to Set HKDF Secret Material." << std::endl; // Handle Error: Setting HKDF Secret Material
		goto err;
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(pctx, context, contextSizeBytes) <= 0) {
		std::cerr << "Error: Failed to Set HKDF Context Info." << std::endl; // Handle Error: Setting HKDF Context Info
		goto err;
	}

	if (EVP_PKEY_derive(pctx, outputBuffer, &outlen) <= 0) {
		std::cerr << "Error: Failed to Derive Key using HKDF." << std::endl; // Handle Error: Deriving Key using HKDF
		goto err;
	}

	ret = true;

err:
	// Clean Up or Handle Errors Here
	if (pctx != NULL) {
		EVP_PKEY_CTX_free(pctx);
	}
	return ret;
}

/*
bool CryptoWrapper::deriveKey_HKDF_SHA256(IN const BYTE* salt, IN size_t saltSizeBytes,
	IN const BYTE* secretMaterial, IN size_t secretMaterialSizeBytes,
	IN const BYTE* context, IN size_t contextSizeBytes,
	OUT BYTE* outputBuffer, IN size_t outputBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY_CTX* pctx = NULL;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if(pctx == NULL)
	{
		printf("failed to get HKDF context\n");
		goto err;	
	}

	// ...	
err:
	EVP_PKEY_CTX_free(pctx);

	return ret;


}
*/

size_t CryptoWrapper::getCiphertextSizeAES_GCM256(IN size_t plaintextSizeBytes)
{
	return plaintextSizeBytes + IV_SIZE_BYTES + GMAC_SIZE_BYTES;
}


size_t CryptoWrapper::getPlaintextSizeAES_GCM256(IN size_t ciphertextSizeBytes)
{
	return (ciphertextSizeBytes > IV_SIZE_BYTES + GMAC_SIZE_BYTES ? ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES : 0);
}

bool CryptoWrapper::encryptAES_GCM256(const BYTE* key, size_t keySizeBytes, const BYTE* plaintext,
	size_t plaintextSizeBytes, const BYTE* aad, size_t aadSizeBytes,
	BYTE* ciphertextBuffer, size_t ciphertextBufferSizeBytes, size_t* pCiphertextSizeBytes)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	int len;
	int ciphertextSize = 0;
	BYTE iv[IV_SIZE_BYTES];

	if (!ctx) {
		std::cerr << "Error: Failed to Create AES-GCM Cipher Context." << std::endl; // Handle Error: Creating AES-GCM Cipher Context
		goto err;
	}

	// Generate Random IV
	if (RAND_bytes(iv, sizeof(iv)) != 1) {
		std::cerr << "Error: Failed to Generate Random IV." << std::endl; // Handle Error: Generating Random IV
		goto err;
	}

	// Initialize Encryption
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
		std::cerr << "Error: Failed to Initialize AES-GCM Encryption." << std::endl; // Handle Error: Initializing AES-GCM Encryption
		goto err;
	}

	// Set IV Length
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, NULL) != 1) {
		std::cerr << "Error: Failed to Set IV Length." << std::endl; // Handle Error: Setting IV Length
		goto err;
	}

	// Initialize Key and IV
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
		std::cerr << "Error: Failed to Set AES-GCM Key and IV." << std::endl; // Handle Error: Setting AES-GCM Key and IV
		goto err;
	}

	// Provide AAD (Additional Authenticated Data)
	if (aad && aadSizeBytes > 0) {
		if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aadSizeBytes) != 1) {
			std::cerr << "Error: Failed to Set AAD." << std::endl; // Handle Error: Setting AAD
			goto err;
		}
	}

	// Encrypt Plaintext
	if (EVP_EncryptUpdate(ctx, ciphertextBuffer + IV_SIZE_BYTES, &len, plaintext, plaintextSizeBytes) != 1) {
		std::cerr << "Error: Failed to Encrypt {pPlaintext." << std::endl; // Handle Error: Encrypting Plaintext
		goto err;
	}
	ciphertextSize = len;

	// Finalize Encryption
	if (EVP_EncryptFinal_ex(ctx, ciphertextBuffer + IV_SIZE_BYTES + ciphertextSize, &len) != 1) {
		std::cerr << "Error: Failed to Finalize Encryption." << std::endl; // Handle Error: Finalizing Encryption
		goto err;
	}
	ciphertextSize += len;

	// Get the Tag
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GMAC_SIZE_BYTES, ciphertextBuffer + IV_SIZE_BYTES + ciphertextSize) != 1) {
		std::cerr << "Error: Failed to Get GCM Tag." << std::endl; // Handle Error: Getting GCM Tag
		goto err;
	}

	// Prepend IV to the Ciphertext
	memcpy(ciphertextBuffer, iv, IV_SIZE_BYTES);

	if (pCiphertextSizeBytes != NULL) {
		*pCiphertextSizeBytes = IV_SIZE_BYTES + ciphertextSize + GMAC_SIZE_BYTES;
	}

	EVP_CIPHER_CTX_free(ctx);
	return true;

err:
	// Clean Up or Handle Errors Here
	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
	}
	return false;
}

/*
bool CryptoWrapper::encryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* plaintext, IN size_t plaintextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* ciphertextBuffer, IN size_t ciphertextBufferSizeBytes, OUT size_t* pCiphertextSizeBytes)
{
	BYTE iv[IV_SIZE_BYTES];
	BYTE mac[GMAC_SIZE_BYTES];
	size_t ciphertextSizeBytes = getCiphertextSizeAES_GCM256(plaintextSizeBytes);
	
	if ((plaintext == NULL || plaintextSizeBytes == 0) && (aad == NULL || aadSizeBytes == 0))
	{
		return false;
	}

	if (ciphertextBuffer == NULL || ciphertextBufferSizeBytes == 0)
	{
		if (pCiphertextSizeBytes != NULL)
		{
			*pCiphertextSizeBytes = ciphertextSizeBytes;
			return true;
		}
		else
		{
			return false;
		}
	}

	if (ciphertextBufferSizeBytes < ciphertextSizeBytes)
	{
		return false;
	}

	// ...
	return false;
}
*/

bool CryptoWrapper::decryptAES_GCM256(const BYTE* key, size_t keySizeBytes, const BYTE* ciphertext,
	size_t ciphertextSizeBytes,	const BYTE* aad, size_t aadSizeBytes,
	BYTE* plaintextBuffer, size_t plaintextBufferSizeBytes, size_t* pPlaintextSizeBytes)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	int len;
	int plaintextSize = 0;
	BYTE iv[IV_SIZE_BYTES];
	BYTE tag[GMAC_SIZE_BYTES];

	if (!ctx) {
		std::cerr << "Error: Failed to Create AES-GCM Cipher Context." << std::endl; // Handle Error: Creating AES-GCM Cipher Context
		goto err;
	}

	// Extract IV from the Beginning of the Ciphertext
	memcpy(iv, ciphertext, IV_SIZE_BYTES);

	// Initialize decryption
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
		std::cerr << "Error: Failed to Initialize AES-GCM Decryption." << std::endl; // Handle Error: Initializing AES-GCM Decryption
		goto err;
	}

	// Set IV Length
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, NULL) != 1) {
		std::cerr << "Error: Failed to Set IV Length." << std::endl; // Handle Error: Setting IV Length
		goto err;
	}

	// Initialize Key and IV
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
		std::cerr << "Error: Failed to Set AES-GCM Key and IV." << std::endl; // Handle Error: Setting AES-GCM Key and IV
		goto err;
	}

	// Provide AAD (Additional Authenticated Data)
	if (aad && aadSizeBytes > 0) {
		if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aadSizeBytes) != 1) {
			std::cerr << "Error: Failed to Set AAD." << std::endl; // Handle Error: Setting AAD
			goto err;
		}
	}

	// Decrypt Ciphertext (Excluding IV and Tag)
	if (EVP_DecryptUpdate(ctx, plaintextBuffer, &len, ciphertext + IV_SIZE_BYTES, ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES) != 1) {
		std::cerr << "Error: Failed to Decrypt Ciphertext." << std::endl; // Handle Error: Decrypting Ciphertext
		goto err;
	}
	plaintextSize = len;

	// Set the Tag
	memcpy(tag, ciphertext + ciphertextSizeBytes - GMAC_SIZE_BYTES, GMAC_SIZE_BYTES);
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GMAC_SIZE_BYTES, tag) != 1) {
		std::cerr << "Error: Failed to Set GCM Tag." << std::endl; // Handle Error: Setting GCM Tag
		goto err;
	}

	// Finalize Decryption
	if (EVP_DecryptFinal_ex(ctx, plaintextBuffer + plaintextSize, &len) != 1) {
		std::cerr << "Error: Failed to Finalize Decryption." << std::endl; // Handle Error: Finalizing Decryption
		goto err;
	}
	plaintextSize += len;

	if (pPlaintextSizeBytes != NULL) {
		*pPlaintextSizeBytes = plaintextSize;
	}

	EVP_CIPHER_CTX_free(ctx);
	return true;

err:
	// Clean Up or Handle Errors Here
	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
	}
	return false;
}

/*
bool CryptoWrapper::decryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* ciphertext, IN size_t ciphertextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* plaintextBuffer, IN size_t plaintextBufferSizeBytes, OUT size_t* pPlaintextSizeBytes)
{
	if (ciphertext == NULL || ciphertextSizeBytes < (IV_SIZE_BYTES + GMAC_SIZE_BYTES))
	{
		return false;
	}

	size_t plaintextSizeBytes = getPlaintextSizeAES_GCM256(ciphertextSizeBytes);
	
	if (plaintextBuffer == NULL || plaintextBufferSizeBytes == 0)
	{
		if (pPlaintextSizeBytes != NULL)
		{
			*pPlaintextSizeBytes = plaintextSizeBytes;
			return true;
		}
		else
		{
			return false;
		}
	}
	
	if (plaintextBufferSizeBytes < plaintextSizeBytes)
	{
		return false;
	}

	// ...
	

	if (pPlaintextSizeBytes != NULL)
	{
		*pPlaintextSizeBytes = plaintextSizeBytes;
	}
	return false;
}
*/

bool CryptoWrapper::readRSAKeyFromFile(IN const char* keyFilename, IN const char* filePassword, OUT KeypairContext** pKeyContext)
{
	// Open the Key File
	FILE* keyFile;
	errno_t err = fopen_s(&keyFile, keyFilename, "r");

	if (err != 0 || !keyFile)
	{
		std::cerr << "Error: Opening Key File Failed." << std::endl; // Handle Error: Openning Key File
		return false;
	}

	// Read Private Key from the Key File
	EVP_PKEY* pkey = PEM_read_PrivateKey(keyFile, NULL, NULL, (void*)filePassword);
	fclose(keyFile);

	if (!pkey)
	{
		std::cerr << "Error: Reading Private Key from Key File Failed." << std::endl; // Handle Error: Reading Private Key from Key File
		return false;
	}

	// Create a Key Context from the Private Key
	*pKeyContext = EVP_PKEY_CTX_new(pkey, NULL);

	if (!*pKeyContext)
	{
		// Clean Up
		EVP_PKEY_free(pkey);

		std::cerr << "Error: Creating Key Context Failed." << std::endl; // Handle Error: Creating Key Context
		return false;
	}

	// Clean Up
	EVP_PKEY_free(pkey);

	return true;
}

/*
bool CryptoWrapper::readRSAKeyFromFile(IN const char* keyFilename, IN const char* filePassword, OUT KeypairContext** pKeyContext)
{
	return false;
}
*/

bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes,
	IN KeypairContext* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
{
	size_t siglen = signatureBufferSizeBytes;

	// Create a Message Digest Context
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

	if (!mdctx)
	{
		std::cerr << "Error: Creating Message Digest Context Failed." << std::endl; // Handle Error: Creating Message Digest Context
		goto err;
	}

	// Initialize Digest Sign Context
	if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, EVP_PKEY_CTX_get0_pkey(privateKeyContext)) <= 0)
	{
		std::cerr << "Error: Initializing Digest Sign Context Failed." << std::endl; // Handle Error: Initializing Digest Sign Context
		goto err;
	}

	// Update Digest Sign Context
	if (EVP_DigestSignUpdate(mdctx, message, messageSizeBytes) <= 0)
	{
		std::cerr << "Error: Updating Digest Sign Context Failed." << std::endl; // Handle Error: Updating Digest Sign Context
		goto err;
	}

	// Finalize Digest Sign Context
	if (EVP_DigestSignFinal(mdctx, signatureBuffer, &siglen) <= 0)
	{
		std::cerr << "Error: Finalizing Digest Sign Context Failed." << std::endl; // Handle Error: Finalizing Digest Sign Context
		goto err;
	}

	// Clean Up
	EVP_MD_CTX_free(mdctx);

	return true;

err:
	// Clean Up or Handle Errors Here
	if (mdctx) {
		EVP_MD_CTX_free(mdctx);
	}

	return false;
}

/*
bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
{
	return false;
}
*/

bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes,
	IN KeypairContext* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result)
{
	// Create a Message Digest Context
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

	if (!mdctx)
	{
		std::cerr << "Error: Creating Message Digest Context Failed." << std::endl; // Handle Error: Creating Message Digest Context
		//Clean Up
		EVP_MD_CTX_free(mdctx);

		return false;
	}

	// Initialize Digest Verify Context
	if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, EVP_PKEY_CTX_get0_pkey(publicKeyContext)) <= 0)
	{
		std::cerr << "Error: Initializing Digest Verify Context Failed." << std::endl; // Handle Error: Initializing Digest Verify Context
		//Clean Up
		EVP_MD_CTX_free(mdctx);

		return false;
	}

	// Update Digest Verify Context
	if (EVP_DigestVerifyUpdate(mdctx, message, messageSizeBytes) <= 0)
	{
		std::cerr << "Error: Updating Digest Verify Context Failed." << std::endl; // Handle Error: Updating Digest Verify Context
		//Clean Up
		EVP_MD_CTX_free(mdctx);

		return false;
	}

	// Finalize Digest Verify Context
	int verifyResult = EVP_DigestVerifyFinal(mdctx, signature, signatureSizeBytes);

	// Clean Up
	EVP_MD_CTX_free(mdctx);

	if (verifyResult == 1)
	{
		*result = true;
		return true;
	}
	else if (verifyResult == 0)
	{
		*result = false;
		return true;
	}
	else
	{
		std::cerr << "Error: Finalizing Digest Verify Context Failed." << std::endl; // Handle Error: Finalizing Digest Verify Context
		*result = false;
		return false;
	}
}

/*
bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result)
{

	return false;
}
*/


void CryptoWrapper::cleanKeyContext(INOUT KeypairContext** pKeyContext)
{
	// Clean Up
	if (*pKeyContext != NULL)
	{
		EVP_PKEY_CTX_free(*pKeyContext);
		*pKeyContext = NULL;
	}
}

bool CryptoWrapper::writePublicKeyToPemBuffer(IN KeypairContext* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(keyContext);
	if (!pkey) {
		return false;
	}

	BIO* bio = BIO_new(BIO_s_mem());
	if (!bio) {
		return false;
	}

	if (!PEM_write_bio_PUBKEY(bio, pkey)) {
		BIO_free(bio);
		return false;
	}

	int keyLength = BIO_pending(bio);
	if (keyLength > publicKeyBufferSizeBytes) {
		BIO_free(bio);
		return false;
	}

	int bytesRead = BIO_read(bio, publicKeyPemBuffer, keyLength);
	BIO_free(bio);

	return (bytesRead == keyLength);
}

/*
bool CryptoWrapper::writePublicKeyToPemBuffer(IN KeypairContext* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	return false;
}
*/

bool CryptoWrapper::loadPublicKeyFromPemBuffer(INOUT KeypairContext* pContext, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	BIO* bio = BIO_new_mem_buf(publicKeyPemBuffer, publicKeyBufferSizeBytes);
	if (!bio) {
		return false;
	}

	EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free(bio);

	if (!pkey) {
		return false;
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_free(pkey);

	if (!ctx) {
		return false;
	}

	pContext = ctx;
	return true;
}

/*
bool CryptoWrapper::loadPublicKeyFromPemBuffer(INOUT KeypairContext* context, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	return false;
}
*/

bool CryptoWrapper::startDh(OUT DhContext** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes) {
	EVP_PKEY_CTX* pctx = NULL;
	EVP_PKEY* params = NULL;
	EVP_PKEY_CTX* kctx = NULL;
	EVP_PKEY* dhkey = NULL;
	BIGNUM* pub_key_bn = NULL;
	size_t key_size = 0;
	bool ret = false;

	// Create a New DH Parameter Generation Context
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
	if (!pctx) {
		std::cerr << "Error: Creating a New DH Parameter Generation Context Failed.\n"; // Handle Error: Creating a New DH Parameter Generation Context
		goto err;
	}

	// Initialize the DH Parameter Generation Context
	if (EVP_PKEY_paramgen_init(pctx) <= 0) {
		std::cerr << "Error: Initializing the DH Parameter Generation Context Failed.\n"; // Handle Error: Initializing the DH Parameter Generation Context
		goto err;
	}

	// Set DH Parameters (3072-Bit Prime)
	if (EVP_PKEY_CTX_set_dh_nid(pctx, NID_ffdhe3072) <= 0) {
		std::cerr << "Error: Setting DH Parameters Failed.\n"; // Handle Error: Setting DH Parameters
		goto err;
	}

	// Generate DH Parameters
	if (EVP_PKEY_paramgen(pctx, &params) <= 0) {
		std::cerr << "Error: Generating DH Parameters Failed.\n"; // Handle Error: Generating DH Parameters
		goto err;
	}

	// Create a New Context for DH Key Generation
	kctx = EVP_PKEY_CTX_new(params, NULL);
	if (!kctx) {
		std::cerr << "Error: Creating New Context for DH Key Generation Failed.\n"; // Handle Error: Creating New Context for DH Key Generation
		goto err;
	}

	// Initialize the DH Key Generation Context
	if (EVP_PKEY_keygen_init(kctx) <= 0) {
		std::cerr << "Error: Initializing the DH Key Generation Context Failed.\n"; // Handle Error: Initializing the DH Key Generation Context
		goto err;
	}

	// Generate the DH Key Pair
	if (EVP_PKEY_keygen(kctx, &dhkey) <= 0) {
		std::cerr << "Error: Generating the DH Key Pair Failed.\n"; // Error: Generating the DH Key Pair
		goto err;
	}

	// Extract the Public Key as BIGNUM
	if (EVP_PKEY_get_bn_param(dhkey, OSSL_PKEY_PARAM_PUB_KEY, &pub_key_bn) <= 0) {
		std::cerr << "Error: Extracting the Public Key as BIGNUM Failed.\n"; // Handle Error: Extracting the Public Key as BIGNUM
		goto err;
	}

	// Check if the Buffer Size is Large Enough to Hold the Key
	key_size = BN_num_bytes(pub_key_bn);
	if (key_size > publicKeyBufferSizeBytes) {
		std::cerr << "Error: Provided Buffer Size is Too Small to Hold the Key.\n"; // Hnadle Error: Provided Buffer Size is Too Small to Hold the Key
		goto err;
	}

	// Convert BIGNUM to Binary and Store in Buffer
	if (BN_bn2bin(pub_key_bn, publicKeyBuffer) <= 0) {
		std::cerr << "Error: Converting BIGNUM Public Key to Binary Public Key Failed.\n"; // Handle Error: Converting BIGNUM Public Key to Binary Public Key
		goto err;
	}

	// Assign the Generated DH Key Pair to the Context
	*pDhContext = dhkey;

	// Ownership Transferred to pDhContext
	dhkey = NULL;

	ret = true;

err:
	// Clean Up or Handle Errors Here
	EVP_PKEY_free(params);
	EVP_PKEY_free(dhkey);
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_CTX_free(kctx);
	BN_free(pub_key_bn);
	if (!ret && *pDhContext) {
		EVP_PKEY_free(*pDhContext);
		*pDhContext = NULL;
	}

	return ret;
}

/*
bool CryptoWrapper::startDh(OUT DhContext** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes)
{
	bool ret = false;
	BIGNUM* p = NULL;
	BIGNUM* g = NULL;
	unsigned char generator = 2;
	

	p = BN_get_rfc3526_prime_3072(NULL);
	if (p == NULL)
	{
		goto err;
	}

	g = BN_bin2bn(&generator, 1, NULL);
	if (g == NULL)
	{
		goto err;
	}

	// ...	

err:
	BN_free(p);
	BN_free(g);

	return ret;


}
*/

bool CreatePeerPublicKey(const BYTE* peerPublicKey, size_t peerPublicKeySizeBytes, EVP_PKEY** genPeerPublicKey)
{
	EVP_PKEY_CTX* ctx = NULL;
	BIGNUM* pubkey_bn = NULL;
	EVP_PKEY* params = NULL;
	bool ret = false;

	// Check the Input Parameters
	if (!peerPublicKey || peerPublicKeySizeBytes == 0 || !genPeerPublicKey) {
		std::cerr << "Error: Invalid Input Parameters in CreatePeerPublicKey.\n"; // Handle Error: Invalid Input Parameters in CreatePeerPublicKey
		goto err;
	}

	// Convert the Raw Public Key to BIGNUM
	pubkey_bn = BN_bin2bn(peerPublicKey, peerPublicKeySizeBytes, NULL);
	if (!pubkey_bn) {
		std::cerr << "Error: Converting the Raw Public Key to BIGNUM Failed.\n"; // Handle Error: Converting the Raw Public Key to BIGNUM
		goto err;
	}

	// Create a New DH Parameter Generation Context
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
	if (!ctx) {
		std::cerr << "Error: Creating a New DH Parameter Generation Context Failed.\n"; // Handle Error: Creating a New DH Parameter Generation Context
		goto err;
	}

	// Initialize the DH Parameter Generation Context
	if (EVP_PKEY_paramgen_init(ctx) <= 0) {
		std::cerr << "Error: Initializing the DH Parameter Generation Context Failed.\n"; // Handle Error: Initializing the DH Parameter Generation Context
		goto err;
	}

	// Set DH Parameters (3072-Bit Prime)
	if (EVP_PKEY_CTX_set_dh_nid(ctx, NID_ffdhe3072) <= 0) {
		std::cerr << "Error: Setting DH Parameters Failed.\n"; // Handle Error: Setting DH Parameters
		goto err;
	}

	// Generate DH Parameters
	if (EVP_PKEY_paramgen(ctx, &params) <= 0) {
		std::cerr << "Error: Generating DH Parameters Failed.\n"; // Handle Error: Generating DH Parameters
		goto err;
	}

	// Create the Peer's Public Key
	*genPeerPublicKey = EVP_PKEY_new();
	if (!*genPeerPublicKey) {
		std::cerr << "Error: Creating the Peer's Public Key Failed.\n"; // Handle Error: Creating the Peer's Public Key
		goto err;
	}

	// Copy the DH Parameters into the Peer's Public Key
	if (EVP_PKEY_copy_parameters(*genPeerPublicKey, params) <= 0) {
		std::cerr << "Error: Copying the DH Parameters into the Peer's Public Key Failed.\n"; // Handle Error: Copying the DH Parameters into the Peer's Public Key
		goto err;
	}

	// Set the Public Key
	if (EVP_PKEY_set1_encoded_public_key(*genPeerPublicKey, peerPublicKey, peerPublicKeySizeBytes) <= 0) {
		std::cerr << "Error: Setting the Public Key Failed.\n"; // Handle Error: Setting the Public Key
		goto err;
	}

	ret = true;

err:
	// Clean Up or Handle Errors here
	EVP_PKEY_CTX_free(ctx);
	BN_free(pubkey_bn);
	EVP_PKEY_free(params);
	if (!ret) {
		EVP_PKEY_free(*genPeerPublicKey);
		*genPeerPublicKey = NULL;
	}

	return ret;
}

/*
bool CreatePeerPublicKey(const BYTE* peerPublicKey, size_t peerPublicKeySizeBytes, EVP_PKEY** genPeerPublicKey)
{

	// ...
	return false;

}
*/

bool CryptoWrapper::getDhSharedSecret(INOUT DhContext* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes)
{
	EVP_PKEY* peer_key = NULL;
	EVP_PKEY_CTX* ctx = NULL;
	size_t secret_len = 0;
	bool ret = false;

	// Check the Input Parameters
	if (!dhContext || !peerPublicKey || !sharedSecretBuffer || peerPublicKeySizeBytes == 0 || sharedSecretBufferSizeBytes == 0) {
		std::cerr << "Error: Invalid Input Parameters in CreatePeerPublicKey.\n"; // Handle Error: Invalid Input Parameters in CreatePeerPublicKey
		goto err;
	}

	// Create the Peer's Public Key
	if (!CreatePeerPublicKey(peerPublicKey, peerPublicKeySizeBytes, &peer_key)) {
		std::cerr << "Error: Creating the Peer's Public Key Failed.\n"; // Handle Error: Creating the Peer's Public Key
		goto err;
	}

	// Create a New Context for Key Derivation
	ctx = EVP_PKEY_CTX_new(dhContext, NULL);
	if (!ctx) {
		std::cerr << "Error: Creating a New Context for Key Derivation Failed.\n"; // Handle Error: Creating a New Context for Key Derivation
		goto err;
	}

	// Initialize the Context for Key Derivation
	if (EVP_PKEY_derive_init(ctx) <= 0) {
		std::cerr << "Error: Initializing the Key Derivation Context Failed.\n"; // Handle Error: Initializing the Key Derivation Context
		goto err;
	}

	// Set the Peer Key for Derivation
	if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
		std::cerr << "Error: Setting the Peer Key for Derivation Failed.\n"; // Handle Error: Setting the Peer Key for Derivation
		goto err;
	}

	// Determine the Length of the Shared Secret
	if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
		std::cerr << "Error: Determining the Shared Secret Length Failed.\n";// Handle Error: Determining the Shared Secret Length
		goto err;
	}

	// Check if the Buffer Size is Large Enough to Hold the Shared Secret
	if (secret_len > sharedSecretBufferSizeBytes) {
		std::cerr << "Error: Provided Buffer Size is Too Small to Hold the Shared Secret.\n"; // Hnadle Error: Provided Buffer Size is Too Small to Hold the Shared Secret
		goto err;
	}

	// Derive the Shared Secret
	if (EVP_PKEY_derive(ctx, sharedSecretBuffer, &secret_len) <= 0) {
		std::cerr << "Error: Deriving the Shared Secret Failed.\n"; // Handle Error: Deriving the Shared Secret
		goto err;
	}

	ret = true;

err:
	// Clean Up or Handle Errors here
	EVP_PKEY_free(peer_key);
	EVP_PKEY_CTX_free(ctx);

	return ret;
}

/*
bool CryptoWrapper::getDhSharedSecret(INOUT DhContext* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes)
{

	bool ret = false;
	EVP_PKEY* genPeerPublicKey = NULL;
	EVP_PKEY_CTX* derivationCtx = NULL;

	if (dhContext == NULL || peerPublicKey == NULL || sharedSecretBuffer == NULL)
	{
		goto err;
	}

	CreatePeerPublicKey(peerPublicKey, peerPublicKeySizeBytes, &genPeerPublicKey);

	// ...

err:
	return ret;
}
*/

void CryptoWrapper::cleanDhContext(INOUT DhContext** pDhContext) {
	// Clean Up
	if (pDhContext && *pDhContext) {
		EVP_PKEY_free(*pDhContext);
		*pDhContext = NULL;
	}
}

/*
void CryptoWrapper::cleanDhContext(INOUT DhContext** pDhContext)
{
	if (*pDhContext != NULL)
	{
		EVP_PKEY_free(*pDhContext);
		*pDhContext = NULL;
	}
}
*/

X509* loadCertificate(const BYTE* certBuffer, size_t certSizeBytes)
{
	// Create a New BIO Memory Buffer
	BIO* bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
	{
		std::cerr << "Error: Creating a New BIO Memory Buffer Failed.\n"; // Handle Error: Creating a New BIO Memory Buffer
		
		return NULL;
	}

	// Write the Certificate Data to the BIO Buffer
	if (BIO_write(bio, (const void*)certBuffer, (int)certSizeBytes) <= 0)
	{
		std::cerr << "Error: Writing the Certificate Date to the BIO Buffer Failed.\n"; // Handle Error: Writing the Certificate Date to the BIO Buffer
		
		// Clean Up
		BIO_free(bio);

		return NULL;
	}

	// Read the X509 Certificate from the BIO Buffer
	X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (cert == NULL)
	{
		std::cerr << "Error: Reading the X509 Certificate from the BIO Buffer Failed.\n"; // Handle Error: Reading the X509 Certificate from the BIO Buffer
	}

	// Clean Up
	BIO_free(bio);

	return cert;
}

/*
X509* loadCertificate(const BYTE* certBuffer, size_t certSizeBytes)
{
	int ret = 0;
	BIO* bio = NULL;
	X509* cert = NULL;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
	{
		printf("BIO_new() fail \n");
		goto err;
	}

	ret = BIO_write(bio, (const void*)certBuffer, (int)certSizeBytes);
	if (ret <= 0)
	{
		printf("BIO_write() fail \n");
		goto err;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (cert == NULL)
	{
		printf("PEM_read_bio_X509() fail \n");
		goto err;
	}

err:
	BIO_free(bio);

	return cert;
}
*/

bool CryptoWrapper::checkCertificate(IN const BYTE* cACcertBuffer, IN size_t cACertSizeBytes, IN const BYTE* certBuffer, IN size_t certSizeBytes, IN const char* expectedCN)
{
	X509* userCert = NULL;
	X509* caCert = NULL;

	X509_STORE* store = NULL;
	X509_STORE_CTX* ctx = NULL;

	bool result = false;

	// Load the CA Certificate
	caCert = loadCertificate(cACcertBuffer, cACertSizeBytes);
	if (caCert == NULL)
	{
		std::cerr << "Error: Loading CA Certificate Failed.\n"; // Handle Error: Loading CA Certificate
		goto err;
	}

	// Load the User Certificate
	userCert = loadCertificate(certBuffer, certSizeBytes);
	if (userCert == NULL)
	{
		std::cerr << "Error: Loading User Certificate Failed.\n"; // Handle Error: Loading User Certificate
		goto err;
	}

	// Create a New Certificate Store
	store = X509_STORE_new();
	if (store == NULL)
	{
		std::cerr << "Error: Creating a New Certificate Store Failed.\n"; // Handle Error: Creating a New Certificate Store
		goto err;
	}

	// Add the CA Certificate to the Store
	if (X509_STORE_add_cert(store, caCert) != 1)
	{
		std::cerr << "Error: Adding the CA Certificate to the Store Failed.\n"; // Handle Error: Adding the CA Certificate to the Store
		goto err;
	}

	// Create a New Certificate Store Context
	ctx = X509_STORE_CTX_new();
	if (ctx == NULL)
	{
		std::cerr << "Error: Creating a New Certificate Store Context Failed.\n"; // Error: Creating a New Certificate Store Context
		goto err;
	}

	// Initialize the Certificate Store Context with the User Certificate and the Store
	if (X509_STORE_CTX_init(ctx, store, userCert, NULL) != 1)
	{
		std::cerr << "X509_STORE_CTX_init() failed\n";
		goto err;
	}

	// Verify the Certificate
	if (X509_verify_cert(ctx) == 1)
	{
		// std::cerr << "Certificate Verified Successfully.\n"; // Certificate Verified

		// Check if the Common Name Matches the Expected Common Name
		if (X509_check_host(userCert, expectedCN, 0, 0, NULL) == 1)
		{
			result = true; // Common Name Matches the Expected Common Name
		}
		else
		{
			std::cerr << "Error: Common Name does not Match the Expected Common Name.\n"; // Handle Error: Common Name does not Match the Expected Common Name
		}
	}
	else
	{
		std::cerr << "Error: Certificate Verification Failed.\n"; // Handle Error: Certificate Verification
	}

err:
	// Clean Up or Handle Errors here
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	X509_free(caCert);
	X509_free(userCert);

	return result;
}

/*
bool CryptoWrapper::checkCertificate(IN const BYTE* cACcertBuffer, IN size_t cACertSizeBytes, IN const BYTE* certBuffer, IN size_t certSizeBytes, IN const char* expectedCN)
{
	int ret = 0;
	X509* userCert = NULL;
	X509* caCert = NULL;


	caCert = loadCertificate(cACcertBuffer, cACertSizeBytes);
	if (caCert == NULL)
	{
		printf("loadCertificate() fail \n");
		goto err;
	}

	userCert = loadCertificate(certBuffer, certSizeBytes);
	if (userCert == NULL)
	{
		printf("loadCertificate() fail \n");
		goto err;
	}

// ...

err:
	X509_free(caCert);
	X509_free(userCert);

	return ret;
}
*/

bool CryptoWrapper::getPublicKeyFromCertificate(const BYTE* certBuffer, size_t certSizeBytes, KeypairContext** pPublicKeyContext)
{
	BIO* bio = NULL;
	X509* cert = NULL;
	EVP_PKEY* pubkey = NULL;

	// Create a BIO Object and Write the Certificate Data
	bio = BIO_new_mem_buf(certBuffer, certSizeBytes);

	if (!bio)
	{
		std::cerr << "Error: Creating BIO Failed." << std::endl; // Handle Error: Creating Bio
		return false;
	}

	// Read and Parse the X.509 Certificate
	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

	if (!cert)
	{
		std::cerr << "Error: Parsing Certificate Failed." << std::endl; // Handle Error: Parsing Certificate

		// Clean Up
		BIO_free(bio);

		return false;
	}

	// Extract the Public Key from the Certificate
	pubkey = X509_get_pubkey(cert);

	if (!pubkey)
	{
		std::cerr << "Error: Extracting Public Key from Certificate Failed." << std::endl; // Handle Error: Extracting Public Key from Certificate

		// Clean Up
		X509_free(cert);

		return false;
	}

	// Create a Key Context from the Public Key
	*pPublicKeyContext = EVP_PKEY_CTX_new(pubkey, NULL);

	if (!*pPublicKeyContext)
	{
		std::cerr << "Error: Creating Public Key Context Failed." << std::endl; // Handle Error: Creating Public Key Context

		// Clean Up
		EVP_PKEY_free(pubkey);
		X509_free(cert);

		return false;
	}

	// Clean Up
	BIO_free(bio);
	EVP_PKEY_free(pubkey);
	X509_free(cert);

	return true;
}

/*
bool CryptoWrapper::getPublicKeyFromCertificate(IN const BYTE* certBuffer, IN size_t certSizeBytes, OUT KeypairContext** pPublicKeyContext)
{

	return false;
}
*/

#endif // #ifdef OPENSSL

/*
* 
* Usefull links
* -------------------------
* *  
* https://www.intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/intrinsics/intrinsics-for-later-gen-core-proc-instruct-exts/intrinsics-gen-rand-nums-from-16-32-64-bit-ints/rdrand16-step-rdrand32-step-rdrand64-step.html
* https://wiki.openssl.org/index.php/OpenSSL_3.0
* https://www.rfc-editor.org/rfc/rfc3526
* 
* 
* Usefull APIs
* -------------------------
* 
* EVP_MD_CTX_new
* EVP_PKEY_new_raw_private_key
* EVP_DigestSignInit
* EVP_DigestSignUpdate
* EVP_PKEY_CTX_new_id
* EVP_PKEY_derive_init
* EVP_PKEY_CTX_set_hkdf_md
* EVP_PKEY_CTX_set1_hkdf_salt
* EVP_PKEY_CTX_set1_hkdf_key
* EVP_PKEY_derive
* EVP_CIPHER_CTX_new
* EVP_EncryptInit_ex
* EVP_EncryptUpdate
* EVP_EncryptFinal_ex
* EVP_CIPHER_CTX_ctrl
* EVP_DecryptInit_ex
* EVP_DecryptUpdate
* EVP_DecryptFinal_ex
* OSSL_PARAM_BLD_new
* OSSL_PARAM_BLD_push_BN
* EVP_PKEY_CTX_new_from_name
* EVP_PKEY_fromdata_init
* EVP_PKEY_fromdata
* EVP_PKEY_CTX_new
* EVP_PKEY_derive_init
* EVP_PKEY_derive_set_peer
* EVP_PKEY_derive_init
* BIO_new
* BIO_write
* PEM_read_bio_X509
* X509_STORE_new
* X509_STORE_CTX_new
* X509_STORE_add_cert
* X509_verify_cert
* X509_check_host
*
*
*
*/
