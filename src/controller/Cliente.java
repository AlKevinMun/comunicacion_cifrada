package controller;

import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class Cliente {
    private boolean continueRunning = true;
    private DatagramSocket socket;
    private InetAddress serverAddress;
    private int port;
    Scanner scanner = new Scanner(System.in);
    KeyPair keys;
    PublicKey serverPublicKey;

    public Cliente(int portValue, String serverIp) throws IOException {
        port = portValue;
        serverAddress = InetAddress.getByName(serverIp);
        socket = new DatagramSocket();
        keys = MyCryptoUtils.randomGenerate(1024);
    }

    public void runClient() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        DatagramPacket packet;
        byte[] receiveData = new byte[7500];
        ByteArrayInputStream is;
        ObjectOutputStream oos;
        System.out.println(keys.getPublic() + " \n- Espacio entre llaves - \n" + keys.getPrivate());
        System.out.printf("Connectat a %s:%d%n", serverAddress.getHostAddress(), port);

        // Enviar el primer mensaje al servidor
        byte[] firstRequestData = getFirstRequest();
        DatagramPacket firstRequestPacket = new DatagramPacket(firstRequestData, firstRequestData.length, serverAddress, port);
        System.out.println("Llave enviada sin problema");
        socket.send(firstRequestPacket);

        // Esperar a recibir la clave pública del servidor
        serverPublicKey = receivePublicKey();
        System.out.println("Recibida clave pública del servidor: " + serverPublicKey);

        while (continueRunning) {
            packet = new DatagramPacket(receiveData, 2048);
            socket.receive(packet);
            processData(packet.getData());
        }
    }

    private PublicKey receivePublicKey() throws IOException {
        byte[] receiveData = new byte[7500];
        DatagramPacket packet = new DatagramPacket(receiveData, receiveData.length);
        socket.receive(packet);
        ByteArrayInputStream is = new ByteArrayInputStream(packet.getData());
        ObjectInputStream ois = new ObjectInputStream(is);
        try {
            byte[] publicKeyBytes = (byte[]) ois.readObject();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IOException("Error al deserializar la clave pública del cliente", e);
        }
    }


    private void processData(byte[] data) {
        ByteArrayInputStream is = new ByteArrayInputStream(data);
        try {
            // Descifrar mensaje recibido del servidor
            byte[] encryptedData = data;
            byte[] decryptedData = MyCryptoUtils.decryptData(encryptedData, keys.getPrivate());
            System.out.println("Mensaje descifrado del servidor: " + new String(decryptedData));

            // Enviar mensaje al servidor con la clave pública recibida
            System.out.println("Inserta el mensaje a enviar: ");
            String message = scanner.nextLine();
            byte[] encryptedMessage = MyCryptoUtils.encryptData(message.getBytes(), serverPublicKey);
            DatagramPacket messagePacket = new DatagramPacket(encryptedMessage, encryptedMessage.length, serverAddress, port);
            socket.send(messagePacket);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }



    // Primer mensaje que se le envía al servidor
    private byte[] getFirstRequest() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(keys.getPublic().getEncoded());
        oos.flush();
        return bos.toByteArray();
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Cliente cvel = new Cliente(5555, "localhost");
        cvel.runClient();
        System.out.println("Parat!");
    }
}
