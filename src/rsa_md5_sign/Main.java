package rsa_md5_sign;

import encryption.*;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class Main {
    public static void main(String[] args) throws Exception {
        final String MSG = "I'm the text to be sent,Lin ChinYoung 2141601010";

        /*
        首先生成两对公钥私钥
         */
        Map<String, Object> senderKeyMap = RSAUtil.initKey();
        RSAPublicKey senderPublicKey = RSAUtil.getpublicKey(senderKeyMap);
        RSAPrivateKey senderPrivateKey = RSAUtil.getPrivateKey(senderKeyMap);

        Map<String, Object> receiverKeyMap = RSAUtil.initKey();
        RSAPublicKey receiverPublicKey = RSAUtil.getpublicKey(receiverKeyMap);
        RSAPrivateKey receiverPrivateKey = RSAUtil.getPrivateKey(receiverKeyMap);

        /*
        发送方使用接受者公钥加密，并用MD5摘要然后自己私钥签名
         */
        Sender sender = new Sender(MSG);
        byte[] cipherText=sender.cipherText(receiverPublicKey);
        byte[] signature=sender.digestAndSign(senderPrivateKey);

        /*
        接受者用自己私钥解密原文，并核对签名
         */
        Receiver receiver =new Receiver();
        receiver.messageReceive(cipherText,signature,senderPublicKey,receiverPrivateKey);
		System.out.println("original message : " + MSG);
		System.out.println("RSA CipherText : " + BytesToHex.fromBytesToHex(cipherText));
        System.out.println("RSA DecryptText : " + receiver.getResult());
        System.out.println("SignVerify : " + receiver.isAccountable());


    }
}
