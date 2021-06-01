package com.johanpmeert;

import net.nullschool.util.DigitalRandom;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jcajce.provider.digest.Keccak;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Locale;


public class Main {

    public static void main(String[] args) throws Exception {
        System.out.println("Ethereum key generator");
        System.out.println("----------------------");
        Keccak.Digest256 kcc = new Keccak.Digest256();
        byte[] digest = kcc.digest("".getBytes(StandardCharsets.UTF_8));
        String kcctest = "C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470";
        System.out.print("\nKeccak-256 testhash of \"\" = " + byteArrayToHexString(digest) + ", should be " + kcctest);
        if (byteArrayToHexString(digest).equals(kcctest)) {
            System.out.println(" ... test SUCCESFULL");
        } else {
            System.out.println(" ... test FAILED");
            System.exit(0);
        }
        final String upperLimit = "F".repeat(56);  // upperlimit for validity of private key
        byte[] random32bytes = new byte[32];
        // SecureRandom sr = new SecureRandom();
        DigitalRandom sr = new DigitalRandom();
        System.out.println("\nUsing Intel DRNG secure random number generator");
        sr.nextBytes(random32bytes);
        String hexRandom = byteArrayToHexString(random32bytes);
        System.out.println("Secure random 32 bytes (HEX): " + hexRandom);
        if (hexRandom.substring(0, 55).equals(upperLimit)) {
            System.out.println("Random number is out of bounds");
            return;
        } else {
            System.out.println("Random number is in valid range");
        }
        //
        // hexRandom = "f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315".toUpperCase(Locale.ROOT); // test private key
        //
        // generate standard ethereum address
        System.out.println("\nPrivate key: " + hexRandom);
        String publicKey = privToPublic(hexRandom).substring(2); // lose the 04 in front
        System.out.println("Public key: " + publicKey);
        String rawEther = byteArrayToHexString(kcc.digest(hexStringToByteArray(publicKey)));
        System.out.println("Keccak-256 hash: " + rawEther);
        String etherAddr = "0x" + rawEther.substring(rawEther.length() - 40).toLowerCase();
        System.out.println("Ether address: " + etherAddr);
        //
        // EIP-55 calculation
        String letters = "abcdef";
        String letters2 = "89abcdef";
        String eip1 = etherAddr.substring(2);
        String eip2 = byteArrayToHexString(kcc.digest(eip1.getBytes())).toLowerCase(); // it's the lowercase string of the address to hash so we use .getBytes(), not the bytearray conversion
        for (int teller = 0; teller < eip1.length(); teller++) {
            if (letters.contains(eip1.substring(teller, teller + 1))) {
                if (letters2.contains(eip2.substring(teller, teller + 1))) {
                    eip1 = eip1.substring(0, teller) + eip1.substring(teller, teller + 1).toUpperCase(Locale.ROOT) + eip1.substring(teller + 1);
                }
            }
        }
        String etherAddEIP55 = "0x" + eip1;
        System.out.println("Ether address EIP-55 (Checksummed): " + etherAddEIP55);
    }


    public static byte[] privToPublic(byte[] address) {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        org.bouncycastle.math.ec.ECPoint pointQ = spec.getG().multiply(new BigInteger(1, address));
        byte[] publickKeyByte = pointQ.getEncoded(false);
        return publickKeyByte;
    }

    public static String privToPublic(String address) {
        return byteArrayToHexString(privToPublic(hexStringToByteArray(address)));
    }

    public static byte[] privToCompressedPublic(byte[] address) {
        ECKey key = ECKey.fromPrivate(address);
        return key.getPubKey();
    }

    public static String privToCompressedPublic(String address) {
        return byteArrayToHexString(privToCompressedPublic(hexStringToByteArray(address)));
    }

    public static byte[] hexStringToByteArray(String hex) {
        hex = hex.length() % 2 != 0 ? "0" + hex : hex;
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(hex.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    public static String byteArrayToHexString(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

}
