import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;

import java.io.*;

public class PGPEncryptionExample {

    public static void decryptFile(String inputFileName, String outputFileName, String privateKeyFileName) throws IOException, PGPException {
        Security.addProvider(new BouncyCastleProvider());

        InputStream encryptedInputStream = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream privateKeyInputStream = new BufferedInputStream(new FileInputStream(privateKeyFileName));
        InputStream decryptedInputStream = decrypt(encryptedInputStream, privateKeyInputStream);

        OutputStream decryptedOutputStream = new BufferedOutputStream(new FileOutputStream(outputFileName));

        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = decryptedInputStream.read(buffer)) != -1) {
            decryptedOutputStream.write(buffer, 0, bytesRead);
        }

        decryptedOutputStream.close();
        decryptedInputStream.close();
        encryptedInputStream.close();
    }

    private static InputStream decrypt(InputStream encryptedInputStream, InputStream privateKeyInputStream) throws IOException, PGPException {
        InputStream decoderInputStream = PGPUtil.getDecoderStream(encryptedInputStream);
        PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(decoderInputStream);

        PGPEncryptedDataList encryptedDataList;
        Object object = pgpObjectFactory.nextObject();

        if (object instanceof PGPEncryptedDataList) {
            encryptedDataList = (PGPEncryptedDataList) object;
        } else {
            encryptedDataList = (PGPEncryptedDataList) pgpObjectFactory.nextObject();
        }

        PGPPBEEncryptedData encryptedData = (PGPPBEEncryptedData) encryptedDataList.get(0);

        InputStream decryptedInputStream = encryptedData.getDataStream(
                new JcePublicKeyDataDecryptorFactoryBuilder()
                        .setProvider("BC")
                        .build(getPrivateKey(privateKeyInputStream))
        );

        PGPObjectFactory plainFactory = new PGPObjectFactory(decryptedInputStream);

        Object message = plainFactory.nextObject();

        if (message instanceof PGPCompressedData) {
            PGPCompressedData compressedData = (PGPCompressedData) message;
            plainFactory = new PGPObjectFactory(compressedData.getDataStream());
            message = plainFactory.nextObject();
        }

        if (message instanceof PGPLiteralData) {
            PGPLiteralData literalData = (PGPLiteralData) message;
            return literalData.getInputStream();
        } else {
            throw new PGPException("Message is not a simple encrypted file - type unknown.");
        }
    }

    private static PGPSecretKey getPrivateKey(InputStream privateKeyInputStream) throws IOException, PGPException {
        InputStream decoderInputStream = PGPUtil.getDecoderStream(privateKeyInputStream);
        PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(decoderInputStream);
        PGPSecretKeyRing secretKeyRing = (PGPSecretKeyRing) pgpObjectFactory.nextObject();
        return secretKeyRing.getSecretKey();
    }

    public static void main(String[] args) {
        String inputFileName = "encryptedFile.pgp";
        String outputFileName = "decryptedFile.txt";
        String privateKeyFileName = "privateKey.asc";

        try {
            decryptFile(inputFileName, outputFileName, privateKeyFileName);
            System.out.println("File decrypted successfully.");
        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }
    }
}
``
