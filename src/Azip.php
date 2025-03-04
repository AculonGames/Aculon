<?php
/**
 * @package Azip
 * @version 1.0
 */
class EncryptException extends Exception {}
class DecryptException extends Exception {}

final class Azip
{
    /**
     * The encryption cipher
     * 
     * @var string $cipher
     */
    const cipher = "aes-256-gcm";
    
    /**
     * Returns a cryptographically-secure encryption key
     * 
     * @return string The randomly-generated key
     */
    public function generate_random_key(): 
    string
    {
        return random_bytes(openssl_cipher_key_length(self::cipher));
    }
    
    /**
     * Returns a cryptographically-secure IV (Initialization Vector)
     * 
     * @return string The randomly-generated IV
     */
    private function generate_random_iv(): 
    string
    {
        return random_bytes(openssl_cipher_iv_length(self::cipher));
    }
    
    /**
     * Concatenates encryption details into a ciphertext
     * 
     * @param string $tag The tag
     * @param string $salt The salt
     * @param string $iv The IV
     * @param string $encrypted The encrypted string
     * 
     * @return string
     */
    private function create_ciphertext(string $tag, string $salt, string $iv, string $encrypted): 
    string
    {
        return $tag . $salt . $iv . $encrypted;
    }
    
    /**
     * Breaks up concatenated encryption details
     * 
     * @param string $concatenated The concatenated string
     * @return array The encryption details
     */
    private function explode_ciphertext(string $concatenated): 
    array
    {
        $tag = substr($concatenated, 0, 16); // 16 bytes for the GCM tag
        $salt = substr($concatenated, 16, 16); // 16 bytes for the salt
        $iv = substr($concatenated, 32, openssl_cipher_iv_length(self::cipher)); // IV length
        $encrypted = substr($concatenated, 32 + openssl_cipher_iv_length(self::cipher), strlen($concatenated) - (32 + openssl_cipher_iv_length(self::cipher))); // Encrypted data
        
        // Return encryption details
        return (array) [
            $tag,
            $salt,
            $iv,
            $encrypted
        ];
    }
    
    /**
     * Encrypts a string using an encryption key
     * 
     * @param string $plaintext The string to be encrypted
     * @param string $password The encryption key
     * 
     * @return string|null The encrypted string
     */
    public function encrypt(string $plaintext, string $password): 
    ?string
    {
        // Generate a random salt (this should be saved and used during decryption)
        $salt = random_bytes(16);
    
        // Use PBKDF2 to derive a secure encryption key from the password and salt
        $iterations = 100000; // More iterations increase security
        $derivedKey = hash_pbkdf2("sha256", $password, $salt, $iterations, 32, false); // 32 bytes for aes-256 key length
        
        // Generate a random IV
        $iv = $this->generate_random_iv();
        $tag = null;
        $options = OPENSSL_RAW_DATA;
    
        // Attempt to encrypt the string
        try {
            // Encrypt the plaintext
            $encrypted = openssl_encrypt($plaintext, self::cipher, $derivedKey, $options, $iv, $tag);
            if ($encrypted === false) {
                throw new EncryptException("Encryption failed");
            }
    
            // Return concatenated result: tag + salt + IV + encrypted data
            return $this->create_ciphertext($tag, $salt, $iv, $encrypted);
        } catch (Exception $e) {
            throw new EncryptException("Encryption failed: " . $e->getMessage());
        }
    }
    
    /**
     * Decrypts an encrypted string using an encryption key
     * 
     * @param string $ciphertext The string to be decrypted
     * @param string $password The decryption key
     * 
     * @return string|null The decrypted string
     */
    public function decrypt(string $ciphertext, string $password): 
    ?string
    {
        // Extract the tag, salt, and IV from the ciphertext
        list($tag, $salt, $iv, $encrypted) = $this->explode_ciphertext($ciphertext);
    
        // Use PBKDF2 to derive the encryption key from the password and salt
        $iterations = 100000;
        $derivedKey = hash_pbkdf2("sha256", $password, $salt, $iterations, 32, false);
    
        // Attempt to decrypt the string
        $options = OPENSSL_RAW_DATA;
        try {
            // Decrypt the data
            $decrypted = openssl_decrypt($encrypted, self::cipher, $derivedKey, $options, $iv, $tag);
            if ($decrypted === false) {
                throw new DecryptException("Decryption failed");
            }
            return $decrypted;
        } catch (Exception $e) {
            throw new DecryptException("Decryption failed: " . $e->getMessage());
        }
    }
}
