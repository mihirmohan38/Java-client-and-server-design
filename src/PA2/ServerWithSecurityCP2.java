package PA2;

import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import java.net.ServerSocket;
import java.net.Socket;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.Cipher;
import java.net.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class ServerWithSecurityCP2 {
	private static final String privatekeyfilename = "C:\\Users\\HP\\Desktop\\ProgrammingAssignment\\src\\PA2\\private_key.der";
	private static final String publickeyfilename = "C:\\Users\\HP\\Desktop\\ProgrammingAssignment\\src\\PA2\\public_key.der";
	private static final String certFileName = "C:\\Users\\HP\\Desktop\\ProgrammingAssignment\\src\\PA2\\server.crt";

	private static final Path certPath = Paths.get(certFileName);
	public static void main(String[] args) {
			try{
				handleClient(args);
			}catch(Exception Ex){}

	}

	public static void handleClient(String[] args) throws Exception{
		int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;
		X509Certificate CAcert;
		CertificateFactory cf;
		try {
			welcomeSocket = new ServerSocket(port); // create new socket
			connectionSocket = welcomeSocket.accept(); // init socket created
			fromClient = new DataInputStream(connectionSocket.getInputStream()); // get input data
			toClient = new DataOutputStream(connectionSocket.getOutputStream()); // output data
			PrivateKey privateKey = loadPrivateKey() ;
			Cipher cipher_d = Cipher.getInstance("RSA/ECB/PKCS1Padding") ;
            cipher_d.init(Cipher.DECRYPT_MODE, privateKey);
            Cipher symCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKey symKey = null;
            SecretKey aesKey = null  ;
			Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding") ;

            boolean haveSymKey; 
			while (!connectionSocket.isClosed()) {

				int greet = fromClient.readInt();
				
				// If the packet is for transferring the filename
				if (greet == 0) {

					System.out.println("Receiving greeting...");

					int numBytesMsg = fromClient.readInt();
					byte [] msg = new byte[numBytesMsg];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(msg, 0, numBytesMsg);
					// return packet type
					toClient.writeInt(0);
					// Now encrypt the message
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					cipher.init(Cipher.ENCRYPT_MODE, privateKey) ;
					cipher.update(msg);

					byte[] encryptedMsg = cipher.doFinal();
					System.out.println("hi " + encryptedMsg.toString());
					// first we send the size of the byte[] to the client
					toClient.writeInt(encryptedMsg.length);
					// then we send the message
					toClient.write(encryptedMsg);
					// Now we handle the certificate request
					int reqCert = fromClient.readInt();
					if(reqCert==1){
						System.out.println("Cert has been requested");
						// reply with packet type 
						toClient.writeInt(1);
						// get cert

						byte[] certData = Files.readAllBytes(certPath);	
						// toClient.writeInt(2);	
						toClient.writeInt(certData.length); // send size
						System.out.println("The cert byte array has size: "+certData.length);
						toClient.write(certData);
						//System.out.println("cert data : \n" + Base64.getEncoder().encodeToString(certData));
						System.out.println("Path to certfile is: "+certPath.toString());
						System.out.println("Cert is actually: "+certData.toString());
						toClient.flush();




						System.out.println("Terminating cert sending");

				    }    }
                else if(greet==4){
                    // means we are getting encrypted key
                    System.out.println("Getting symmetric key");
                    int encryptedKeyLength = fromClient.readInt();
                    byte[] encryptedKey = new byte[encryptedKeyLength];
                    fromClient.readFully(encryptedKey,0,encryptedKeyLength);
                    byte[] decryptedKeyByteArr = cipher_d.doFinal(encryptedKey);
                    symKey = new SecretKeySpec(decryptedKeyByteArr,"AES");
					aesKey = new SecretKeySpec(decryptedKeyByteArr, 0, decryptedKeyByteArr.length, "AES");

                    aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
					System.out.println("extraced aes key");
					System.out.println(aesKey.toString());
                }
					// Now we handle successful AP
                else if(greet==2){
                    // This means auth was a success and client is sending a file
                    int byteFileNameSize = fromClient.readInt();
                    byte[] encryptedFileName = new byte[byteFileNameSize];
                    fromClient.readFully(encryptedFileName,0,byteFileNameSize);
                    PublicKey publicKey = loadPublicKey();
                    // Now we decrypt the filename
					//symCipher.init(Cipher.DECRYPT_MODE, symKey);
					//System.out.println("encry file name si : " + Base64.getEncoder().encodeToString(encryptedFileName));
                    byte[] decrypted_sgmt  = aesCipher.doFinal(encryptedFileName) ; // byte[] of filename
                    int numBytes = decrypted_sgmt.length;
                    //symCipher.init(Cipher.DECRYPT_MODE, symKey);
                    

                    //
//						cipher.init(Cipher.DECRYPT_MODE,publicKey);
//						byte[] byteFileName = cipher.doFinal();
                    String fileName = new String(decrypted_sgmt, "UTF-8");
                    System.out.println("The name of the file is: "+fileName); // works!
                    fileOutputStream = new FileOutputStream("recv_"+new String(decrypted_sgmt, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
                    
                    //byte[] encryptedFileName = cipher.doFinal()
                }

					/*
					fileOutputStream = new FileOutputStream("recv_"+new String(msg, 0, numBytesMsg));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
					*/

				// If the packet is for transferring a chunk of the file
				 else if (greet == 3) {
					int encryptedBufferSize = fromClient.readInt();
					//System.out.println("Encrypted buffer size is: "+encryptedBufferSize);
					int numBytes = fromClient.readInt();
					byte[] block = new byte[encryptedBufferSize];
					fromClient.readFully(block, 0, encryptedBufferSize);
					byte[] decryptedBlock = aesCipher.doFinal(block);
					if (numBytes > 0) {
						bufferedFileOutputStream.write(decryptedBlock, 0, numBytes);
						bufferedFileOutputStream.flush();
					}
					if (numBytes < 117) {
						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
					}
				}
				else if(greet==21){
					System.out.println("File transmission is complete");
					System.out.println("_______________________________");
					fileOutputStream = null;
					bufferedFileOutputStream = null;
				}
                
				}

			
		} catch (Exception e) {e.printStackTrace();}
	}


	public static PrivateKey loadPrivateKey() throws Exception {
        Path privateKeyPath = Paths.get(privatekeyfilename);
        byte[] privateKeyByteArray = Files.readAllBytes(privateKeyPath);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        return privateKey;
    }
  
	public static PublicKey loadPublicKey() throws Exception{
		byte[] keyBytes = Files.readAllBytes(Paths.get(publickeyfilename));
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
	  

}
