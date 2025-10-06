Project 2 for CyberSecurity

In the second project, we extended the **mySNS** system by adding functionalities that allow **multiple users** to use the same server and **share files securely** between them. We implemented **user authentication** and **access control mechanisms** to ensure that only authorized users can access or modify specific files. Each user—such as doctors and patients—has unique credentials and permissions managed through their **Java keystores**, which store the necessary keys and certificates for secure communication. We also improved the server to handle multiple clients simultaneously and to maintain secure associations between users and their stored data. This phase focused on strengthening the system’s security by introducing identity verification, controlled access to resources, and safe sharing of encrypted and signed files between authenticated users.


Group members: Laura, Maria Beatriz, Maria Rita 


doctors: alice e jose
users: bob e maria


How to use the program:
On server, on file mySNSServer.java on src/server directory Run As Java Aplication on eclipse
Then:
Open terminal on this: ~/eclipse-workspace/SEG/src/client$
and execute the following:
java mySNS.java -a 127.0.0.1:23456 -m alice -u bob -sc opa.pd cifras2.pdf file2.txt
java mySNS.java -a 127.0.0.1:23456 -m alice -u bob -sa opa.pd cifras2.pdf file2.txt
java mySNS.java -a 127.0.0.1:23456 -m alice -u bob -se opa.pd cifras2.pdf file2.txt
java mySNS.java -a 127.0.0.1:23456 -u bob -g cifras2.pdf file1.txt
