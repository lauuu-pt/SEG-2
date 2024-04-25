package server;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class mySNSServer {
	/*Membros do grupo:
	Laura Tomás (58641)
	Maria Beatriz Guerreiro (58643)
	Maria Rita Gonçalves (58659)*/
	
	/**
     * Método principal para iniciar o servidor mySNS.
     * @param args Argumentos da linha de comando.
	 * @throws IOException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException {
        var server = new mySNSServer();
        Scanner scanner = new Scanner(System.in);
        System.out.println("Passe do admin para iniciar o servidor: ");
        String input = scanner.nextLine();
        
        if(input.equals("123456")) {
        	System.out.println("passe correta");
            File passwordFile = new File("/home/aluno-di/eclipse-workspace/SEG-2/src/server", "users.txt");
            
            if(passwordFile.createNewFile()) { 
            		Scanner scanner2 = new Scanner(System.in);
                    System.out.println("ficheiro de users não exite, digite a passe do admin para cria-lo: ");
                    String input2 = scanner2.nextLine();
                    if(input2.equals(input)) {
	                	try (BufferedWriter writer = new BufferedWriter(new FileWriter(passwordFile))) {                    	                
	            	    	adcUser("admin", input , writer);
	            	        System.out.println("Arquivo de texto criado com sucesso: users.txt");
	            	        writer.close();
	            	        
	            	        escreveMAC(passwordFile.getAbsolutePath(), input);
	            	        System.out.println("MAC escrito");

	            	        Boolean a = verificaMAC(passwordFile.getAbsolutePath(), input);
	                    	if(a) {
	                    		System.out.println("MAC verificado: OK");
	                    		server.startServer();
	                    	}else {
	                    		System.out.println("MAC verificado: NOK\nServidor fechado");
	                    		return;
	                    	}
	            	        
	                    	server.startServer();
                	}
            	}else {
            		System.out.println("passe errada, servidor fechado");
            	    return;
                }
            }else {
            	
            	File mac = new File("/home/aluno-di/eclipse-workspace/SEG-2/src/server", "users.txt.mac");
            	
            	if(mac.exists()) {
            		Boolean a = verificaMAC(passwordFile.getAbsolutePath(), input);
                	if(a) {
                		System.out.println("MAC verificado: OK");
                		server.startServer();
                	}else {
                		System.out.println("MAC verificado: NOK\nServidor fechado");
                		return;
                	}
            	}else {
            		Scanner scanner3 = new Scanner(System.in);
                    System.out.println("o mac do ficheiro users.txt nao existe\nDeseja escreve-lo?\n(responda com s para sim ou n para nao)");
                    String input3 = scanner3.nextLine();
                    
                    if(input3.equals("s")) {
                    	escreveMAC(passwordFile.getAbsolutePath(), input);
            	        System.out.println("MAC escrito");

            	        Boolean a = verificaMAC(passwordFile.getAbsolutePath(), input);
                    	if(a) {
                    		System.out.println("MAC verificado: OK");
                    		server.startServer();
                    	}else {
                    		System.out.println("MAC verificado: NOK\nServidor fechado");
                    		return;
                    	}
                    }else if(input3.equals("n")){
                    	System.out.println("Voce deve proteger as suas senhas\nservidor fechado");
                    	return;
                    }else {
                    	System.out.println("sua resposta deveria ser s ou n e você digitou: "+ input3 +"\nServidor fechado");
                    	return;
                    }                    
            	}            	            	            	
            }            
            
        }
        else {
        	System.out.println("Passe errada, servidor fechado");
        	return;
        }
    }

    
    /**
     * Método para iniciar o servidor.
     */
    public void startServer(){
    	System.out.println("\nServidor aberto");
        try (var sSoc = new ServerSocket(23456)) {
            while (true) {
                try {
                    var inSoc = sSoc.accept();
                    var newServerThread = new ServerThread(inSoc);                 
                    	newServerThread.start();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e1) {
			e1.printStackTrace();
		}
    }

    
    /**
     * Classe interna que implementa uma thread do servidor para cada cliente.
     */
    class ServerThread extends Thread {
        private Socket socket;

        
        /**
         * Construtor da classe ServerThread.
         * @param inSoc Socket para a conexão do cliente.
         */
        ServerThread(Socket inSoc) {
            socket = inSoc;
            System.out.println("Thread do servidor para cada cliente\n");
        }

        
        /**
         * Método que executa a thread do servidor.
         */
        public void run() {
        	
            try (var outStream = new ObjectOutputStream(socket.getOutputStream());
                 var inStream = new ObjectInputStream(socket.getInputStream())) {

                String user = null;
                Boolean bool = null;
                String cond = null;
                String pass = null;
                
                File userDirectory = null;
                Boolean allFilesReceived = null; 
                
                File passwordFile = new File("/home/aluno-di/eclipse-workspace/SEG-2/src/server", "users.txt");

                try{

                    user = (String) inStream.readObject();
                    pass = (String) inStream.readObject();
                    bool = (Boolean) inStream.readObject();
                    cond = (String) inStream.readObject();        
                    Boolean var = null;
                    
                    System.out.println("Thread: depois de receber o utilizador\n");
  
	                } catch (ClassNotFoundException e1) {
	                    e1.printStackTrace();
					}
                                
                if(!bool) {

                	if(cond.equals("-au")){
		                userDirectory = new File("/home/aluno-di/eclipse-workspace/SEG-2/src/server", user);
		                if (!userDirectory.exists()) {
		                    if (userDirectory.mkdirs()) {
		                    	outStream.writeObject(true);
		                        System.out.println("Criado um diretorio para o utilizador: " + user);		                    			                        
			                    Long fileSize = (Long) inStream.readObject();
				                
			            	    if (fileSize == -1) {
			            	        System.out.println("O cliente acabou de enviar o certificado.");
			            	    }
			            	    
			                    System.out.println("Recebendo certificado...");
	
		                        
			                	String nameCertificado = (String) inStream.readObject(); 
			                	File certDirectory = new File("/home/aluno-di/eclipse-workspace/SEG-2/src/server/certificados");
			                	var outputFile = new File(certDirectory, nameCertificado);
			                	
			             	    try (var outFileStream = new FileOutputStream(outputFile);
			             	         var outFile = new BufferedOutputStream(outFileStream)) {
			             	        byte[] buffer = new byte[1024];
			             	        int bytesRead;
			             	        long remainingBytes = fileSize;
			             	        while (remainingBytes > 0 && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, remainingBytes))) != -1) {
			             	            outFile.write(buffer, 0, bytesRead);
			             	            remainingBytes -= bytesRead;
			             	        }
			             	        System.out.println("Certificado: " + nameCertificado+ " recebido");

			             	        
			             	    } catch (IOException e) {
			             	        e.printStackTrace();
			             	        allFilesReceived = false;			             	    
								}
	                    	}
		                    
		                    BufferedWriter writer2 = new BufferedWriter(new FileWriter(passwordFile, true));
	             	        adcUser(user, pass, writer2);
	             	        writer2.close();
		                    System.out.println(user + " adicionado em users.txt");
		                }
		                else {
		                	System.out.println("Utilizador: " + user+ " ja existe");
		                	outStream.writeObject(false);
		                	return;
		                }

            		}else {
		                try {
		                	
		                	while (true) {
		                	    Long fileSize = (Long) inStream.readObject();
		                	    if (fileSize == -1) {
		                	        System.out.println("O cliente acabou de enviar os ficheiros.");
		                	        break;
		                	    }
		                	    
		                	    String filename = (String) inStream.readObject();
		                	    
				                allFilesReceived = true;

		                	    
		                	    var outputFile = new File(userDirectory, filename);
		                	    try (var outFileStream = new FileOutputStream(outputFile);
		                	         var outFile = new BufferedOutputStream(outFileStream)) {
		                	        byte[] buffer = new byte[1024];
		                	        int bytesRead;
		                	        long remainingBytes = fileSize;
		                	        while (remainingBytes > 0 && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, remainingBytes))) != -1) {
		                	            outFile.write(buffer, 0, bytesRead);
		                	            remainingBytes -= bytesRead;
		                	        }
		                	    } catch (IOException e) {
		                	        e.printStackTrace();
		                	        allFilesReceived = false;
		                	    }
		
		                	    System.out.println("Fim do ficheiro: " + filename);
		                	}
	
	
		                } catch (EOFException e) {
		                
		                    System.err.println("Cliente desconectou do servidor.");
		                    allFilesReceived = false; 
		                } catch (ClassNotFoundException e1) {
		                    e1.printStackTrace();
		                    allFilesReceived = false; 
		                }
	
	                
		                outStream.writeObject(allFilesReceived); 
		                System.out.println("Transferencia dos ficheiros do servidor reconhecida: " + allFilesReceived);
	                }
	                
                }else {
                	System.out.println("aqui");
                	int fileCount = inStream.readInt();
                    System.out.println("Client will send " + fileCount + " files.");
                    List<String> existingFiles = new ArrayList<>();
                    List<File> FilesServer = new ArrayList<File>();
                    for (int i = 0; i < fileCount; i++) {
                        // Read the filename from the client
                        String filename = (String) inStream.readObject();
                        System.out.println("Received filename: " + filename);
                    // Check if any file on the server starts with the received filename
                        
                    File serverDirectory = new File("/home/aluno-di/eclipse-workspace/SEG/src/server", user);
                    File[] filesInDirectory = serverDirectory.listFiles();
                    if (filesInDirectory != null) {
                        for (File file : filesInDirectory) {
                            if (file.exists() && file.isFile() && file.getName().startsWith(filename)) {
                                existingFiles.add(file.getName());
                                FilesServer.add(file);
                                
                            }
                        }
                    }
                }

                // Inform the client about the filenames that already exist on the server
                //ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
                System.out.println(existingFiles);
                System.out.println("no files: "+existingFiles.size());
                //int existingFilesSize=existingFiles.size();
                int existingFileSize = existingFiles.size();
                outStream.writeObject(existingFileSize); // Send the count of existing files
                outStream.flush();
                for(int j =0; j<existingFileSize; j++) {
                	File ficheiro=FilesServer.get(j);
                	outStream.writeObject(ficheiro.getName());
                	outStream.writeObject(ficheiro.length());
                	
                	 try (BufferedInputStream cifradoFileB = new BufferedInputStream(new FileInputStream(ficheiro))) {
                         byte[] buffer = new byte[1024];
                         int bytesRead;
                         while ((bytesRead = cifradoFileB.read(buffer, 0, 1024)) > 0) {
                        	 outStream.write(buffer, 0, bytesRead);
                         }
                         System.out.println("ficheiro "+ficheiro.getName()+" enviado");
                     }
                	 outStream.flush();
                }

               
                    
                }}catch (IOException e) {
	                System.err.println("Erro na comunicação com o cliente: " + e.getMessage());
	                if (e instanceof EOFException) {
	                    System.err.println("O cliente encerrou abruptamente a conexão.");
	                } else if (e instanceof SocketException) {
	                    System.err.println("Erro de socket: " + e.getMessage());
	                }
	            } catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidKeySpecException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} finally {
	                try {
	                    socket.close();
	                    System.out.println("Conexão com o cliente encerrada.");
	                } catch (IOException e) {
	                    System.err.println("Erro ao fechar o socket: " + e.getMessage());
	                }
	            }
            
        
        }
    }

 // Método para adicionar um novo usuário ao arquivo de senhas
    private static void adcUser(String username, String password, BufferedWriter writer) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException {
        // Gera um salt aleatório
        byte[] salt = generateSalt();

        // Gera a senha hasheada usando PBKDF2 com SHA-256
        String hashedPassword = hashPassword(password, salt);

        // Escreve as informações do usuário no arquivo de senhas
        writer.write(username + ";" + Base64.getEncoder().encodeToString(salt) + ";" + hashedPassword);
        writer.newLine();
        
        try {
        File mac = new File("/home/aluno-di/eclipse-workspace/SEG/src/server", "users.txt.mac");
        File pass = new File("/home/aluno-di/eclipse-workspace/SEG/src/server", "users.txt");
        if(mac.exists()) {
        	mac.delete();
        	
        	escreveMAC(pass.getAbsolutePath(), "123456");
        	System.out.println("MAC atualizado");
        	verificaMAC(pass.getAbsolutePath(), "123456");//Tem q passar  apasse do admin
        }
        }finally {
        	
        }
        
        
    }

    // Método para gerar um salt aleatório
    private static byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    // Método para hashear a senha usando PBKDF2 com SHA-256
    private static String hashPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 10000;
        int keyLength = 256;

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = factory.generateSecret(spec).getEncoded();

        return Base64.getEncoder().encodeToString(hash);
    }
    
    
 public static void escreveMAC(String filename, String pass) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		
  		//Cria fileIn(le o conteudo) e fileOu(escreve o conteudo)
  		FileInputStream fis = new FileInputStream(filename);
  		FileOutputStream fos = new FileOutputStream(filename + ".mac");
  		
  		//especifica a password
  		byte [] password = pass.getBytes();
  		SecretKeySpec key = new SecretKeySpec(password, "hmacSHA256");
  		
  		
  		//instancia do mac
  		Mac m = Mac.getInstance("hmacSHA256");
  		m.init(key);
  		
  		byte [] b = new byte[16];
  		int i = fis.read(b);
  		
  		//percorre o ficheiro
  		while (i != -1) {
  			m.update(b,0,i);
  			i = fis.read(b);
  		}
  		
  		//calcula o mac
  		byte [] mac  = m.doFinal();
  		
  		fos.write(mac);
  		fos.close();
  		fis.close();
  		
  	}

 	public static Boolean verificaMAC(String filename, String pass) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		
		try (
				
			FileInputStream fis = new FileInputStream(filename);
			FileInputStream fisMAC = new FileInputStream(filename + ".mac")) {
			
			//especifica a password
			byte [] password = pass.getBytes();
			SecretKeySpec key = new SecretKeySpec(password, "hmacSHA256");
	
			//instancia do mac
			Mac m = Mac.getInstance("hmacSHA256");
			m.init(key);
			
			byte [] b = new byte[16];
			int i = fis.read(b);
			
			//percorre o ficheiro
			while (i != -1) {
				m.update(b,0,i);
				i = fis.read(b);
			}
			
			//calcula o mac
			byte [] mac  = m.doFinal();
					
			byte [] macToBeVerified = new byte[fisMAC.available()];
			fisMAC.read(macToBeVerified);
			
			String s_mac = Base64.getEncoder().encodeToString(mac);	
			String s_macToBeVerified = Base64.getEncoder().encodeToString(macToBeVerified);
			
			if (s_mac.equals(s_macToBeVerified)) {
				return true;
				
			} else {
				return false;
			}
			
		} catch (IllegalStateException e) {
			e.printStackTrace();
		}
		return null;
		}

}