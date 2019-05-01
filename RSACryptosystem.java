
package rsa.cryptosystem;

/**
 *
 * @author Eoin Reid  
 * www.github.com/EoinReid
 */
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

public class RSACryptosystem {

    public static void main(String[] args) {
    // Key Generation //
        
        // Alice choses two 2 large prime numbers p != q randomly and independently.
            // Create a bitLength of 2048 as this is the NIST(National Institute of Standards and Technology) recommended bit lenght for RSA Encryption
            // Create a SecureRandom generator to be used to randomly generate numbers securely (the normal new Random uses a Linear Congruential Generator making it unsecure)
        int bl = 2048;
        Random r = new SecureRandom();
        Random r2 = new SecureRandom();
            // Randomly generates the 2 large prime numbers p & q, using .probablePrime method that returns a BigInteger that is most likely prime 
            //(The probability that a BigInteger returned by this method is 2^)-100
            // It uses the bit length and a random generator object as its parameters
        BigInteger p = BigInteger.probablePrime(bl, r);
        BigInteger q = BigInteger.probablePrime(bl, r2);
        
        
        // Alice computes N = p*q   
            // To compute N we have to use the .multiply method from the BigInteger class instead of the usual * operator as the math operators usually used on integers do not work on numbers this large
        BigInteger n = p.multiply(q);

        // public key is = N and e 
        // Alice then choses an integer e, which is coprime to ϕ(N) 
        //ϕ(N) = (P-1)(Q-1)  
        // e is the public key exponent
            // Have to create a BigInteger object with the value = 1 to use to carry out the subract by 1 part of the ϕ(N) calculation
        BigInteger bi = new BigInteger("1");
        BigInteger phi = ( p.subtract(bi)).multiply(q.subtract(bi));
        
        
            // e = 65537 as this is commonly used as a public exponent in RSA as it is a common compromise of speed over complexity 
            //as raising the e exponent would slow down the algorithm, and lowering the e exponent would make it more insecure
        BigInteger e = new BigInteger("65537");
        
        
        // If statements to make sure e follows the conditions:
        // e must be an 1 < e < phi
        // e must be coprime to ϕ(N)   
       
        
       if(e.compareTo(phi) == 1){
           // if e is gretaer than phi, it will throw an exception to stop the program as e is too large and must be a smaller number.
           throw new IllegalArgumentException("exponent value too large, please choose a smaller value.");
       }
       if(!e.isProbablePrime(100)){
           // if e is not probablePrime with 100% certantity then it will throw an exception to stop the program as e must be prime
           throw new IllegalArgumentException("exponent value must be prime.");
       }

        // private key is = N and d 
        // d is the private key exponent
        BigInteger d = e.modInverse(phi);
        
    // Encryption Example //
                
      String plainText = "I cant wait for my exams";
      System.out.println("Plaintext (before encryption) = " +plainText);      
        // To turn the String M into a numerical value we can use for the caluclations im using the getBytes() method which converts a string into bytes and retusn an array of bytes we can use
      BigInteger m = new BigInteger(plainText.getBytes());   
        // Then we get the new m value and caluclate m to the power of n^e and convert that to a byte[] array using the encryption method pasing the public key and the byte values array of m
        byte[] cipherText = enc(n,e,m);
     System.out.println("Cipertext = " +Arrays.toString(cipherText));
      
     
    // Decryption Example // 
       BigInteger decryptedMsg = (new BigInteger(cipherText)).modPow(d, n);
       String decryptedmsg = dec(n,d,cipherText);
       System.out.println("Plaintext (After decryption) = " +decryptedmsg);

        
    }

    public static byte[] enc(BigInteger n, BigInteger e, BigInteger m){
        // To encrypt a message using rsa we have to pass the parameters n (which is p*q), and its exponent e. n^e makes up the public key & BigInteger m which is the bytes values of the plaintext message.        
            // To Encrypt we do the caluclation of m to the power of n^e, and convert it to a byte array
            // In other words putting the value of the plaintext message to the power of the public key will get us our encrypted message
            // We then convert it back into a byte array and return it.
      byte[] cipherText = m.modPow(e, n).toByteArray();
      return cipherText;
      
          
    }
    
    public static String dec(BigInteger n, BigInteger d, byte[] cipherText ){
       // To decrypt a message using rsa we have to pass the parameteres n, its exponent d, n^d makes up the private key & byte[] cipherText which is the byte array fo the encrypted message values.       
           // To decrypt we do the calulcation of cipherText (casted as a BigInteger) to the power of n^d (which is the private key)
           // We then create a new string to return the decryptedmsg (the plaintext), converted back into a byte array casted as a string.
    BigInteger decryptedMsg = (new BigInteger(cipherText)).modPow(d, n);
    String decryptedmsg = new String(decryptedMsg.toByteArray());
       return decryptedmsg;
    }

}
