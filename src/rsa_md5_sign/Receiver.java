package rsa_md5_sign;

import encryption.BytesToHex;
import encryption.Md5Util;
import encryption.RSAUtil;

import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Created by vicky on 2018/1/7.
 */
public class Receiver {
    private  String result;
    private  boolean accountable;
    public void messageReceive(byte[] cipherText , byte[] signature, RSAPublicKey senderPublicKey, RSAPrivateKey receiverPrivateKey) throws Exception {
        System.out.println();
        System.out.println("==========messageReceive=========");

        byte[] plainResult = RSAUtil.decrypt(cipherText, receiverPrivateKey);
        result =new String(plainResult);
        byte[] md5Digest = Md5Util.messageDigest(result);
        Signature signCheck = Signature.getInstance("MD5withRSA");
        signCheck.initVerify(senderPublicKey);
        signCheck.update(result.getBytes());
        accountable = signCheck.verify(signature);

        System.out.println("RSA CipherText : " + BytesToHex.fromBytesToHex(cipherText));
        System.out.println("RSA DecryptText : " + result);
        System.out.println("SignVerify : " + accountable);
        System.out.println("==================================");
        System.out.println();

    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public boolean isAccountable() {
        return accountable;
    }

    public void setAccountable(boolean accountable) {
        this.accountable = accountable;
    }

}
