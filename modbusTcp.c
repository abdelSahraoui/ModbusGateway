#include <stdio.h>
#include <stdlib.h>
#include "modbus.h"
#include <errno.h>

//#define SLAVE_ID 1 // ID du périphérique esclave Modbus RTU
#define SLAVE_ADR 6 // rang dans la trame
#define FUNCTION_CODE 7 // 
#define REGISTER_ADR 8 // 
#define REGISTER_VAL 10 // 

int main(void) {
    modbus_t *mbrtu = NULL;
    modbus_t *mbtcp = NULL;
    int server_socket = -1;
    int client_socket = -1;
    int rc=-1;
    const char* portSerie = "/dev/ttyACM0";
    const int baudrate = 9600;
    const char parity = 'N'; // Pas de parité
    const int data_bits = 8;
    const int stop_bits = 1;

    const char* ip_address = "0.0.0.0"; // écoute sur toutes les interfaces
    const int port = 1502;
    
    uint16_t transaction=0; 
    uint16_t length=0; 
    uint8_t slaveAdr=0;
    uint8_t codeFunction=0;
    
    uint8_t adrRegL =0;
    uint8_t adrRegH=0;
    uint16_t adrReg = 0;
    
    uint8_t dataL =0;
    uint8_t dataH =0;
    uint16_t data = 0;

   
    // Création du contexte Modbus TCP
    mbtcp = modbus_new_tcp(ip_address, port);
    if (mbtcp == NULL) {
        fprintf(stderr, "Erreur lors de la création du contexte Modbus TCP\n");
        exit(EXIT_FAILURE);
    }

    // Configuration du contexte Modbus TCP comme serveur
    server_socket = modbus_tcp_listen(mbtcp, 1); // 1 pour une connexion en attente
    if (server_socket == -1) {
        fprintf(stderr, "Échec de l'écoute sur le port Modbus TCP\n");
        modbus_free(mbtcp);
        exit(EXIT_FAILURE);
    }
    printf("En attente de connexions Modbus TCP sur le port %d ...\n", port);

    while(1)
    {
                // Accepter la connexion entrante
        
        client_socket = modbus_tcp_accept(mbtcp, &server_socket);
        if (client_socket == -1) {
            fprintf(stderr, "Erreur lors de l'acceptation de la connexion Modbus TCP\n");
            modbus_close(mbtcp);
            modbus_free(mbtcp);
            exit(EXIT_FAILURE);
        }
        printf("Client Modbus TCP connecté\n");
        
         // Création du contexte Modbus RTU 
        mbrtu = modbus_new_rtu(portSerie, baudrate, parity, data_bits, stop_bits);
        if (mbrtu == NULL) {
                fprintf(stderr, "Erreur lors de la création du contexte Modbus RTU\n");
                exit(EXIT_FAILURE);
            }
        else 
        {
            printf("contexte Modbus RTU OK\n");
            // Connexion Modbus RTU
            if (modbus_connect(mbrtu) == -1) {
                fprintf(stderr, "Connexion Modbus RTU impossible: %s\n", modbus_strerror(errno));
                modbus_free(mbrtu);
                exit(EXIT_FAILURE);
            }
            printf("Connexion Modbus RTU OK\n");
            
        }
        
        
        
    
    


        while(1)
        {
        
        // Attendre les requêtes Modbus et afficher les données reçues
        uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
        
        rc = modbus_receive(mbtcp, query);
        if (rc > 0) 
        {
            //data = (query[REGISTER_VAL] << 8 )+ query[REGISTER_VAL+1] ;
            //printf("taille uint8 %d octets: ", sizeof(uint8_t));
            transaction = query[0]<<8;
            transaction += query[1];
            length =  query[4]<<8;
            length += query[5];
            
            slaveAdr = query[SLAVE_ADR];
            
            codeFunction = query[FUNCTION_CODE];
            
            adrRegH = query[REGISTER_ADR] ;
            adrRegL = query[REGISTER_ADR+1] ;
            adrReg = (adrRegH<<8) + adrRegL;
            
            dataH = query[REGISTER_VAL] ;
            dataL = query[REGISTER_VAL+1] ;
            data = (dataH<<8) + dataL;
            printf("Requête reçue de taille : %d octets, data : %x, fonction : %d\n => ", rc,data,codeFunction);
            for (int i = 0; i < rc; ++i) {
                printf("%02X ", query[i]);
            }
            printf("\n");
            printf("Id transaction: %d, len: %d, slave adresse: %d, function: %d , register: %x, data: %x\n", transaction,length,slaveAdr, codeFunction,adrReg, data);  
        } 
        else if (rc == -1) {
            fprintf(stderr, "Déconnexion ou erreur lors de la réception de la requête Modbus TCP: %s\n", modbus_strerror(errno));
            break;
        }
        
        
        //Partie envoie
        if(codeFunction==0x06)
        {
            // Écriture de la valeur data à l'adresse adrReg
            // Définir l'identifiant de l'esclave
            modbus_set_slave(mbrtu, slaveAdr);
            rc = modbus_write_register(mbrtu, adrReg, data);
            if (rc == -1) {
                fprintf(stderr, "Erreur d'écriture du registre Modbus RTU: %s\n", modbus_strerror(errno));
                //modbus_close(mbrtu);
                //modbus_free(mbrtu);
                //exit(EXIT_FAILURE);
            }
            else 
            {
                printf("Valeur %02X  envoyée avec succès à l'adresse 0 en utilisant Modbus RTU\n",data);
                // EN TETE TRAME TCPMODBUS
                // exemple de reponse au protocole modbusTcp
                //  ID  MBT  LEN  SL FC 1ER   Nb 
                // 0001 0000 0006 01 06 1000 0001 
                // 0001 0203 0405 06 07 0809 1011
                
                uint8_t *data8 = malloc(12*sizeof(uint8_t));
                data8[0] = transaction>>8;
                data8[1] = transaction&0xFF;
                data8[2] = 0x00;
                data8[3] = 0x00;
                uint16_t len = 6;
                data8[4] = len>>8;
                data8[5] = len&0xFF;
                data8[6] = slaveAdr;
                data8[7] = codeFunction;
                data8[8] = adrRegH;
                data8[9] = adrRegL;
                data8[10] = 0x00;
                data8[11] = 0x01; // on écrit qu'un seul registre à la fois ici
                
                rc = send(client_socket, data8, 12, 0);
                if (rc == -1) 
                {
                    printf("%d \n",rc);
                    fprintf(stderr, "Erreur d'acquiteement Modbus TCP d'ecriture de registres \n");
                    
                    //modbus_close(mbtcp);
                    //modbus_free(mbtcp);
                    //exit(EXIT_FAILURE);
                }
                else 
                {
                    printf("rc : %d\n",rc); 
                    printf("Acquiteement Modbus TCP d'ecriture de registres avec succès.\n");
                }
                free(data8);
            }
        }
        
        
        if(codeFunction==0x03)
        {
            // Lire les n valeurs à partir de l'adresse adrReg        
            //rc = modbus_write_register(mbrtu, adrReg, data);
            
            uint16_t dataLength = data;
                       
            uint16_t *data16 = malloc(dataLength*sizeof(uint16_t));
            uint8_t *data8 = malloc(2*dataLength*sizeof(uint8_t)+9);
            // Définir l'identifiant de l'esclave
            
            
            modbus_set_slave(mbrtu, slaveAdr);
            
            rc = modbus_read_registers(mbrtu, adrReg, dataLength, data16); //Remplacer le 0 par adrReg
              
            if (rc == -1) {
                fprintf(stderr, "Erreur de lecture du registre Modbus RTU: %s\n", modbus_strerror(errno));
                //modbus_close(mbrtu);
                //modbus_free(mbrtu);
                //exit(EXIT_FAILURE);
            }
            else
            {
                 
                printf("%d données recues avec succès à l'adresse %02X en utilisant Modbus RTU\n",rc,adrReg);
                
                
                // EN TETE TRAME TCPMODBUS
                // exemple de reponse au protocole modbusTcp
                //  ID  MBT  LEN  SL FC S  ***********
                // 0001 0000 0007 01 03 04 00 03 a9 1c 
                // 0001 0203 0405 06 07 08 09 10 11 12
                data8[0] = transaction>>8;
                data8[1] = transaction&0xFF;
                data8[2] = 0x00;
                data8[3] = 0x00;
                uint16_t len = dataLength*2 +3;
                data8[4] = len>>8;
                data8[5] = len&0xFF;
                data8[6] = slaveAdr;
                data8[7] = codeFunction;
                data8[8] = dataLength*2;
                
                
                
                
                for(int i = 0; i<dataLength;i++)                 
                {
                    //printf("%02X ",data16[i]);
                    //printf("\n");
                    // On transforme le tableau de mots de 16 bits en tableau de mots de 8 bits
                    data8[2*i+9] = data16[i]>>8;
                    data8[2*i+1+9] = data16[i]&0xFF;
                    printf("%02X ",data8[2*i]);printf("%02X ",data8[2*i+1]);
                    printf("\n");                    
                }
                
                
               
                //rc = modbus_send_raw_request(mbtcp,data8,2*dataLength);
                // Envoi direct de données au client via le socket
                rc = send(client_socket, data8, 2*dataLength+9, 0);
                              
                        
                if (rc == -1) 
                {
                    printf("%d \n",rc);
                    fprintf(stderr, "Erreur lors de l'envoi des données Modbus TCP\n");
                    
                    //modbus_close(mbtcp);
                    //modbus_free(mbtcp);
                    //exit(EXIT_FAILURE);
                }
                else 
                {
                    printf("rc : %d\n",rc); 
                    printf("Données envoyées avec succès.\n");
                }
            }
            printf("free data16 and data8 memory ................");
            printf("\n");
            free(data16);
            free(data8);
        }
        
        
    
        }

     // Fermeture de la connexion et libération de la mémoire
    modbus_close(mbrtu);
    modbus_free(mbrtu);
    close(client_socket);
    }
    
    return 0;
}
