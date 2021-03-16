package com.encrypt;

import com.google.crypto.tink.*;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.util.Assert;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

@Slf4j
@SpringBootApplication
public class EncryptApplication implements CommandLineRunner {

    public static void main(String[] args) {
        SpringApplication.run(EncryptApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        AeadConfig.register();

        //Создание ключа (необходимо один раз)
        //createKeySet();

        final String plainText = "number of card";

        //Шифруем
        final byte[] ciphertext = encrypt(plainText);
        //Дешифруем
        final byte[] decrypt = decrypt(ciphertext);

        Assert.isTrue(plainText.equals(new String(decrypt)), "encrypt value != decrypt value");
    }


    //создание ключа
    //на диск сохранять, конечно, это плохо, нужно в какой-нибудь KVS, но...
    private void createKeySet() throws IOException, GeneralSecurityException {
        final KeysetHandle keysetHandle = KeysetHandle.generateNew(AesGcmKeyManager.aes128GcmTemplate());
        String keysetFilename = "my_keyset.json";
        CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(new File(keysetFilename)));
    }


    //Шифруем
    private byte[] encrypt(String plainText) throws IOException, GeneralSecurityException {
        String keysetFilename = "my_keyset.json";
        KeysetHandle keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withFile(new File(keysetFilename)));

        Aead aead = keysetHandle.getPrimitive(Aead.class);
        log.info("Text for encrypt [{}]", plainText);
        byte[] ciphertext = aead.encrypt(plainText.getBytes(StandardCharsets.UTF_8), null);
        log.info("Encrypted text [{}]", new String(Base64.getEncoder().encode(ciphertext), StandardCharsets.UTF_8));
        return ciphertext;
    }

    //Дешифруем
    private byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException, IOException {
        String keysetFilename = "my_keyset.json";
        KeysetHandle keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withFile(new File(keysetFilename)));

        Aead aead = keysetHandle.getPrimitive(Aead.class);

        final String base64PlainText = new String(Base64.getEncoder().encode(ciphertext), StandardCharsets.UTF_8);
        log.info("Plain decrypt text [{}]", base64PlainText);

        final byte[] bytes = Base64.getDecoder().decode(base64PlainText);
        final boolean equals = Arrays.equals(ciphertext, bytes);
        log.info("Eq two arr [{}]", equals);

        byte[] decrypted = aead.decrypt(ciphertext, null);
        log.info("Decrypt text [{}]", new String(decrypted));
        return decrypted;
    }

}
