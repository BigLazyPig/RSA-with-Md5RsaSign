package rsa_md5_sign;

import encryption.BytesToHex;
import encryption.Md5Util;
import encryption.RSAUtil;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Created by vicky on 2018/1/7.
 */
public class Sender {
    private String message;
    public Sender(String mes) {
        this.message=mes;
    }

    public byte[] cipherText(RSAPublicKey receiverPublicKey) throws Exception {
        System.out.println();
        System.out.println("===========EncryptStarted==========");
        byte[] rsaResult = RSAUtil.encrypt(message.getBytes(),receiverPublicKey);
        System.out.println("original message : " + message);
        System.out.println("RSA CipherText : " + BytesToHex.fromBytesToHex(rsaResult));
        System.out.println("=================================");
        System.out.println();
        return rsaResult;
    }
    public byte[] digestAndSign(RSAPrivateKey senderPrivateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        System.out.println();
        System.out.println("===========SignStarted==========");
        Signature signature = Signature.getInstance("MD5withRSA");//初始化签名
        signature.initSign(senderPrivateKey);
        signature.update(message.getBytes());//MD5摘要后签名
        byte[] sign =    signature.sign();
        System.out.println("sender sign  "+ BytesToHex.fromBytesToHex(sign));
        System.out.println("=================================");
        System.out.println();
        return sign ;
    }
}
