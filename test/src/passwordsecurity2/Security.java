//////////////////////////////////////////////////////////////////////////
// TODO:                                                   		        //
// Uloha2: Vytvorit funkciu na hashovanie.              DONE            //
// Je vhodne vytvorit aj dalsie pomocne funkcie napr. na porovnavanie   //
// hesla ulozeneho v databaze so zadanym heslom.        DONE            //
//////////////////////////////////////////////////////////////////////////
package passwordsecurity2;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Security {
    
    protected static byte[] getSalt() throws NoSuchAlgorithmException {
        /*
        *   Salt treba generovat cez secure funkciu.
        */
    	SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }
    
    private static String toHex(byte[] array) throws NoSuchAlgorithmException {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0)
        {
            return String.format("%0"  + paddingLength + "d", 0) + hex;
        }else{
            return hex;
        }
    }
    
    protected static String generatePswd(String heslo) throws NoSuchAlgorithmException, InvalidKeySpecException {
    	byte[] salt = getSalt();
    	int iterations = 500;
    	char[] chars = heslo.toCharArray();
    	
    	PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();
    	
    	return toHex(hash) + ":" + toHex(salt);
    }
    
    protected static boolean validatePswd(String incPaswd, String storedPswd) throws NoSuchAlgorithmException, InvalidKeySpecException {
    	String[] parts = storedPswd.split(":");
        int iterations = 500;
        byte[] salt = fromHex(parts[1]);
        byte[] hash = fromHex(parts[2]);
         
        PBEKeySpec spec = new PBEKeySpec(incPaswd.toCharArray(), salt, iterations, hash.length * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] testHash = skf.generateSecret(spec).getEncoded();
         
        int diff = hash.length ^ testHash.length;
        for(int i = 0; i < hash.length && i < testHash.length; i++)
        {
            diff |= hash[i] ^ testHash[i];
        }
        return diff == 0;
    }
    
    protected static byte[] fromHex(String hex) throws NoSuchAlgorithmException
    {
        byte[] bytes = new byte[hex.length() / 2];
        for(int i = 0; i<bytes.length ;i++)
        {
            bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }
    
    
}

