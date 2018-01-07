package encryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by vicky on 2018/1/7.
 */
public class Md5Util {
    public static byte[] messageDigest(String plainText) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update(plainText.getBytes());
        return messageDigest.digest();
        }
    }

