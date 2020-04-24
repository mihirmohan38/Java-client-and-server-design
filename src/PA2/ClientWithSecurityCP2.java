package PA2;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.Scanner;

public class ClientWithSecurityCP2 {
    public static void main(String[] args) throws Exception {

        // need to make it more robust - check for gibberish
        String serverAddress = "localhost";
        if (args.length > 1) serverAddress = args[0];

        int port = 4321;
        if (args.length > 2) port = Integer.parseInt(args[1]);

        int numBytes = 0;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        long timeStarted = System.nanoTime();

        System.out.println("Establishing connection to server...");

        // Connect to server and get the input and output streams
        clientSocket = new Socket(serverAddress, port);
        toServer = new DataOutputStream(clientSocket.getOutputStream());
        fromServer = new DataInputStream(clientSocket.getInputStream());


        // Start of Authentication Protocol
        PublicKey CAPublicKey = ExtractPubKey("C:\\Users\\HP\\Desktop\\ProgrammingAssignment\\src\\PA2\\cacse.crt", null) ;
        String message = "Hello SecStore, please prove your identity";
        byte[] encrypted_msg = greet(clientSocket , toServer, fromServer, message) ;
        PublicKey publicKey = null  ;
        try {
            publicKey = getCertificate(clientSocket, toServer, fromServer, CAPublicKey);
        }catch (Exception e){
            e.printStackTrace();}
        //Boolean authentic = true ;
        Boolean authentic = authenticate(message, encrypted_msg, publicKey) ;
        if(publicKey == null) System.out.println(" the publicKey is null ");
        if (!authentic) System.out.println("The server is not authentic");
        else{
            // send symmetric key over
            SecretKey key =  SendSymmetricKey(toServer, publicKey) ;
            System.out.println("Authentication and AES key transfer took: " + (System.nanoTime() - timeStarted)/1000000.0 + "ms to run");
            // Exchange information Part 2
            String filename = null ;
            while(true){

                String[] arguments = readInput() ;
                timeStarted = System.nanoTime() ;
                if(arguments[0].contains("send")) {
                    if (arguments.length >= 2){
                        filename =  arguments[1] ;
                        System.out.println(filename);
                        System.out.println("Starting file transfer");
                        try {
                            EncryptFileAndSend(arguments[1], key, toServer);
                            System.out.println("File Transfer of " + filename + " took: " + (System.nanoTime() - timeStarted)/1000000.0 + "ms to run");
                        }catch (FileNotFoundException e){
                            System.out.println("You have entered an invalid file address, Please check you address or add a full path  ");
                        }
                    }else{
                        System.out.println("Client : incomplete command ");
                    }

                }else if (arguments[0].contains("exit")){
                    System.out.println("Ending session with " + serverAddress + "/" + port);
                    break ;
                }else {
                    System.out.println("Invalid command : Please use command 'send <file path>'  or 'exit'. ");
                }


            }

        }
    }

    public static SecretKey SendSymmetricKey(DataOutputStream toServer, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        // generate secret key using AES algorithm
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES") ;
        keyGenerator.init(128);
        SecretKey symmetricKey = keyGenerator.generateKey() ;
        //create encrypting cipher
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding") ;
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        //sending the encrypted symmetric key over
        byte[] encrypted_key = cipher.doFinal(symmetricKey.getEncoded()) ;
        toServer.writeInt(4);
        toServer.writeInt(encrypted_key.length);
        toServer.write(encrypted_key);
        System.out.println("client : the symmetric key is sent to the authorized server ");
        System.out.println(symmetricKey);
        return symmetricKey ;

    }



    public static void EncryptFileAndSend(String name, SecretKey publicKey,  DataOutputStream toServer) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //encrypts files in the block size of 117 bytes and sends onto the output stream
        // creating the encryption cipher

        String filename = "C:\\Users\\HP\\Desktop\\ProgrammingAssignment\\src\\PA2\\"+ name ;


        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding") ;
        cipher.init(Cipher.ENCRYPT_MODE, publicKey) ;

        // Open the file
        FileInputStream fileInputStream = new FileInputStream(filename);
        BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

        // Send the filename
        toServer.writeInt(2);
        byte[] encryptedFilename = cipher.doFinal(name.getBytes()) ;
        toServer.writeInt(encryptedFilename.length);
        toServer.write(encryptedFilename);
        toServer.flush();



        byte [] fromFileBuffer = new byte[117];

        // Send the file
        for (boolean fileEnded = false; !fileEnded;) {
            int numBytes = bufferedFileInputStream.read(fromFileBuffer);
            fileEnded = numBytes < 117;
            byte[] encrypted_sgmt =  cipher.doFinal(fromFileBuffer) ;

            //System.out.println("hello " + numBytes);
            toServer.writeInt(3);
            toServer.writeInt(encrypted_sgmt.length);
            //System.out.println("Encrypted segment length is: "+encrypted_sgmt.length);
            toServer.writeInt(numBytes);
            toServer.write(encrypted_sgmt);
            toServer.flush();
            
        }

        bufferedFileInputStream.close();
        fileInputStream.close();
        toServer.writeInt(21);// tell server that file sending is complete
    }

    public static PublicKey ExtractPubKey(String address, PublicKey toVerify) throws FileNotFoundException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if(address == "" || address == null) address = "C:\\Users\\HP\\Desktop\\ProgrammingAssignment\\src\\PA2\\server.crt";
        // do I have to decrypt the certificate here ?
        InputStream fis = new FileInputStream(address) ; //("server.crt"); // certificate location after extraction
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert =(X509Certificate)cf.generateCertificate(fis);
        PublicKey key = cert.getPublicKey();
        if (toVerify != null) cert.verify(toVerify);   // verification of certificate

        return key ;
    }

    public static byte[] greet(Socket socket, DataOutputStream toServer, DataInputStream fromServer, String message) throws IOException {
        // send a message and receive the encrypted message
        // should change to nonce
        byte[] byteMsg = message.getBytes() ;
        System.out.println("Client : Sending greetings");

        toServer.writeInt(0) ; // This is for the server, specifying that this is a greet
        // do I even need to send a message ? Protocol discussion : then delete
        toServer.writeInt(byteMsg.length) ; // This is for the server, specifying the length of the byte stream.
        toServer.write(byteMsg); // is there some pre-requisite message that needs to go here
        toServer.flush();

        System.out.println("Client : waiting for encrypted message");


        // receive encrypted message
        int packetType = fromServer.readInt() ;
        if (packetType != 0 ) return null ;
        int size = fromServer.readInt() ;
        byte[] encryptedMsg = new byte[size] ;
        fromServer.readFully(encryptedMsg, 0, size);

        System.out.println("Client : received encrypted message");

        return encryptedMsg  ;
    }

    public static PublicKey getCertificate(Socket socket, DataOutputStream toServer, DataInputStream fromServer, PublicKey publicKey) throws IOException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        System.out.println("Client : requesting for certificate" );
        toServer.writeInt(1);
        toServer.flush();

        //getting and storing the certificate
        int packetType = fromServer.readInt() ;


        if (packetType == 1 ){
            int size = fromServer.readInt() ;
            //byte[] encryptedMsg = getBytes(fromServer) ;
            byte[] encryptedMsg = new byte[size];
            fromServer.readFully(encryptedMsg, 0 , size );
            System.out.println("client : size of received certificate is " + size);


            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream certInputStream = new ByteArrayInputStream(encryptedMsg);
            X509Certificate signedCertificate = (X509Certificate) cf.generateCertificate(certInputStream);

            //signedCertificate.checkValidity();
            signedCertificate.verify(publicKey);
            System.out.println("Signed certificate validity checked and verified");

            // extract public key from server's signed certificate
            PublicKey serverPublicKey = signedCertificate.getPublicKey();
            return serverPublicKey ;



        }
        return null ;

    }

    public static Boolean authenticate(String message , byte[] encryptedMsg , PublicKey publicKey) throws Exception {
        // decrypt and compare
        // should deal with a hashed message digest instead
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding") ;
        //PublicKey key = loadPublicKey() ;
        //cipher.init(Cipher.DECRYPT_MODE, key);
        cipher.init(Cipher.DECRYPT_MODE, publicKey) ;
        byte[] bytes_d = cipher.doFinal(encryptedMsg) ;
        if (Base64.getEncoder().encodeToString(bytes_d).contains(Base64.getEncoder().encodeToString(message.getBytes()))) return true ;
        return false ;
    }

    public static String[] readInput(){
        Scanner myObj = new Scanner(System.in);  // Create a Scanner object
        System.out.println(">>");
        String argument = myObj.nextLine();  // Read user input
        String[] arguments = argument.split(" ") ;
        return arguments ;
        //System.out.println("Username is: " + arguments[0]);  // Output user input
    }

}

