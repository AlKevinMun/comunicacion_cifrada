package controller;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class Servidor {
    DatagramSocket socket;
    int port;
    boolean continueRunning = true;
    Scanner scanner = new Scanner(System.in);
    KeyPair keys;
    PublicKey clientKeys;
    InetAddress clientIP;
    int clientPort;
    boolean first;

    public Servidor(int portValue) throws IOException {
        socket = new DatagramSocket(portValue);
        port = portValue;
        keys = MyCryptoUtils.randomGenerate(1024);
    }

    public void runServer() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        DatagramPacket packet;
        byte[] sendingData = new byte[5000];
        ByteArrayInputStream is;
        ObjectOutputStream oos;
        first = true;

        System.out.println("Servidor iniciado");

        // Esperar a recibir un mensaje del cliente antes de enviar la clave pública
        clientKeys = receivePublicKey();
        System.out.println("Recibida clave pública del cliente: " + clientKeys);

        // Enviar la clave pública del servidor al cliente
        byte[] serverPublicKeyData = getPublicKeyData();
        DatagramPacket serverPublicKeyPacket = new DatagramPacket(serverPublicKeyData, serverPublicKeyData.length, clientIP, clientPort);
        System.out.println("Llave enviada sin problema");
        socket.send(serverPublicKeyPacket);

        // Enviar un mensaje inicial al cliente
        if (first) {
            System.out.println("Inserta el mensaje a enviar: ");
            String initialMessage = scanner.nextLine();
            byte[] messageBytes = initialMessage.getBytes();
            DatagramPacket initialMessagePacket = new DatagramPacket(messageBytes, messageBytes.length, clientIP, clientPort);
            socket.send(initialMessagePacket);
            first = false;
        }


        while (continueRunning) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }

            packet = new DatagramPacket(sendingData, 2048);
            socket.receive(packet);
            processData(packet.getData());
        }
        socket.close();
    }

    private PublicKey receivePublicKey() throws IOException {
        byte[] receiveData = new byte[7500];
        DatagramPacket packet = new DatagramPacket(receiveData, receiveData.length);
        socket.receive(packet);
        ByteArrayInputStream is = new ByteArrayInputStream(packet.getData());
        ObjectInputStream ois = new ObjectInputStream(is);
        clientIP = packet.getAddress();
        clientPort = packet.getPort();
        try {
            byte[] publicKeyBytes = (byte[]) ois.readObject();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IOException("Error al deserializar la clave pública del cliente", e);
        }
    }

    private byte[] getPublicKeyData() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(keys.getPublic().getEncoded());
        oos.flush();
        return bos.toByteArray();
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
            byte[] encryptedMessage = MyCryptoUtils.encryptData(message.getBytes(), clientKeys);
            DatagramPacket messagePacket = new DatagramPacket(encryptedMessage, encryptedMessage.length, clientIP, port);
            socket.send(messagePacket);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Servidor srvVel = new Servidor(5555);
        srvVel.runServer();
        System.out.println("Parat!");
    }
}
