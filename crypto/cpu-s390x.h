
/**
 * Definitions to determine the direction of the symmetric
 * encryption/decryption functions.
 */
#define ICA_ENCRYPT 1
#define ICA_DECRYPT 0

/**
 * Symetric encryption/decryption modes
 */
#define MODE_ECB		1
#define MODE_CBC		2
#define MODE_CFB		3
#define MODE_OFB		4
#define MODE_CTR		5
#define MODE_XTS		6
#define MODE_GCM		7
#define MODE_CBCCS		8
#define MODE_CCM		9

/**
 * SHA Message parts
 */
#define SHA_MSG_PART_ONLY	0
#define SHA_MSG_PART_FIRST	1
#define SHA_MSG_PART_MIDDLE	2
#define SHA_MSG_PART_FINAL	3

/**
 * Context for SHA256 and SHA224 operations
 */
typedef struct {
	uint64_t runLen;
	unsigned char sha256Hash[SHA256_DIGEST_LENGTH];
} sha256_context_t;

/**
 * Context for SHA512 and SHA384 operations
 */
typedef struct {
	uint64_t runLenHigh;
	uint64_t runLenLow;
	unsigned char sha512Hash[SHA512_DIGEST_LENGTH];
} sha512_context_t;
