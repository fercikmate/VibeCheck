#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <mosquitto.h>
#include <fcntl.h>
#include <errno.h>

#define MQTTPORT 1883
#define SSDPPORT 1900
#define HTTPPORT 8080
#define SSDP_ADDR "239.255.255.250"

// Global device information
const char *ssdp_usn = "Kontroler";
const char *ssdp_nts = "device:alive";
const char *ssdp_st = "ssdp:projekat";
const char *ssdp_location = "None"; // or idk
// Global control variable
static volatile int running = 1;

// Function prototype for sendg/get_ssdp_message
void send_ssdp_message(int sockfd, struct sockaddr_in *dest_addr, const char *type);
// void get_ssdp_message(int sockfd, struct sockaddr_in *dest_addr,const char* type) ;

void *multicast_listener(void *arg)
{
    int ssdp_sockfd;
    struct sockaddr_in addr, sender_addr;
    struct ip_mreq mreq;
    char msgbuf[1024];
    socklen_t sender_len = sizeof(sender_addr);

    ssdp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ssdp_sockfd < 0)
    {
        perror("Multicast socket creation failed");
        pthread_exit(NULL);
    }

    // Allow multiple sockets to use the same PORT number
    int reuse = 1;
    if (setsockopt(ssdp_sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0)
    {
        perror("Setting ReuseAddr failed");
        close(ssdp_sockfd);
        pthread_exit(NULL);
    }

    // bind
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(SSDPPORT);

    if (bind(ssdp_sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Multicast bind failed");
        close(ssdp_sockfd);
        pthread_exit(NULL);
    }
    // Join the multicast group
    mreq.imr_multiaddr.s_addr = inet_addr("239.255.255.250");
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(ssdp_sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0)
    {
        perror("IP_ADD_MEMBERSHIP failed");
        close(ssdp_sockfd);
        pthread_exit(NULL);
    }
    printf("Controller SSDP listening on 239.255.255.250:%d...\n\n", SSDPPORT);

    // Make socket non-blocking
    int flags = fcntl(ssdp_sockfd, F_GETFL, 0);
    fcntl(ssdp_sockfd, F_SETFL, flags | O_NONBLOCK);

    // Send initial Msearch announcement
    send_ssdp_message(ssdp_sockfd, NULL, "M-SEARCH"); // send msearch on start to everzyone

    // listen for multicast messages
    while (running)
    {
        fd_set read_fds;
        struct timeval timeout;
        int retval;
        FD_ZERO(&read_fds);
        FD_SET(ssdp_sockfd, &read_fds);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        retval = select(ssdp_sockfd + 1, &read_fds, NULL, NULL, &timeout);
        if (retval == -1)
        {
            perror("select failed");
            break;
        }
        if (FD_ISSET(ssdp_sockfd, &read_fds))
        {
            int nbytes = recvfrom(ssdp_sockfd, msgbuf, sizeof(msgbuf) - 1, 0,
                                  (struct sockaddr *)&sender_addr, &sender_len);
            if (nbytes < 0)
            {
                if (errno != EWOULDBLOCK && errno != EAGAIN)
                {
                    perror("Multicast recv failed");
                }
            }
            else
            {
                msgbuf[nbytes] = '\0';

                //   if (strstr(msgbuf, "USN") != NULL){ // TODO  select only the devices with names
                //  printf("Received from %s:\n%s\n", inet_ntoa(sender_addr.sin_addr), msgbuf); print address
                if (strstr(msgbuf, "NOTIFY") != NULL)
                {
                    if (strstr(msgbuf, "NT: ssdp:projekat") != NULL && strstr(msgbuf, "NTS: ssdp:alive") != NULL)
                    {
                        printf("ALIVE received: %s\n", msgbuf);
                        //           get_ssdp_message(ssdp_sockfd, &sender_addr, "alive");
                        // TODO add to device list
                        // mosquitto_publish(mosq, NULL, "VibeCheck/control/status", strlen("connected"), "connected", 0, false);
                    }
                    if (strstr(msgbuf, "NT: ssdp:projekat") != NULL && strstr(msgbuf, "NTS: ssdp:byebye") != NULL)
                    {
                        printf("BYEBYE received: %s\n", msgbuf);
                        //   get_ssdp_message(ssdp_sockfd, &sender_addr, "byebye");
                        // TODO remove from device list
                    }
                }
                else if (strstr(msgbuf, "HTTP/1.1 200 OK") != NULL && strstr(msgbuf, "ST: ssdp:projekat\r\n") != NULL)
                {
                    printf("RESPONSE received: %s\n", msgbuf);
                    // TODO but can be done her get_ssdp_message(ssdp_sockfd, &sender_addr, "response");
                    // TODO add to device list
                    // mosquitto_publish(mosq, NULL, "VibeCheck/control/status", strlen("connected"), "connected", 0, false);
                }
                //  }
            }
        }
    }
    // Send byebye announcement before exiting
    printf("Shutting down SSDP.\n");

    close(ssdp_sockfd);
    ssdp_sockfd = -1;
    printf("SSDP listener stopped.\n");
    pthread_exit(NULL);
}

// create thread function to start SSDP
void ssdp_start()
{
    pthread_t ssdp_thread;
    running = 1;
    pthread_create(&ssdp_thread, NULL, multicast_listener, NULL);
    pthread_detach(ssdp_thread); // Let it run independently
}

// Signal the thread to stop
void ssdp_stop()
{
    running = 0;
    // send byebye
    sleep(1);
}

void send_ssdp_message(int sockfd, struct sockaddr_in *dest_addr, const char *type)
{
    char message[512];
    struct sockaddr_in target_addr; // Local variable for the target address

    // If dest_addr is NULL, create a multicast target address
    if (dest_addr == NULL)
    {
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        target_addr.sin_addr.s_addr = inet_addr(SSDP_ADDR); // Multicast address
        target_addr.sin_port = htons(SSDPPORT);
        dest_addr = &target_addr; // Point to our local address structure
    }
    if (strcmp(type, "M-SEARCH") == 0)
    {
        snprintf(message, sizeof(message),
                 "M-SEARCH * HTTP/1.1\r\n"
                 "HOST: %s:%d\r\n"
                 "MAN: \"ssdp:discover\"\r\n"
                 "MX: 3\r\n"
                 "ST: ssdp:projekat\r\n" // type of searched device
                 "\r\n",
                 SSDP_ADDR, SSDPPORT);
    }
    else
    {
        fprintf(stderr, "Controller should only send M-SEARCH, not: %s\n", type);
        return;
    }
    int sent_bytes = sendto(sockfd, message, strlen(message), 0,
                            (struct sockaddr *)dest_addr, sizeof(*dest_addr));
    if (sent_bytes < 0)
    {
        perror("SSDP sendto failed");
    }
    else
    {
        printf("SSDP %s message sent:\n%s\n", type, message);
    }
}


void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
    if (rc == 0)
    {
        puts("Subscribing to topics...");
        mosquitto_subscribe(mosq, NULL, "VibeCheck/control/status", 0);
        puts("Subscribed successfully.");
    }
    else
    {
        mosquitto_disconnect(mosq);
        perror("Failed to connect to broker");
    }
}

void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
    // Print the topic for the first message received, then disconnect
    printf("Topic: %s\n", msg->topic);
    mosquitto_disconnect(mosq);
}

void on_publish(struct mosquitto *mosq, void *obj, int mid)
{
    printf("Message %d has been published.\n", mid);
}

void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
    if (rc != 0)
    {
        puts("Unexpected disconnection.");
    }
    else
    {
        puts("Disconnected from broker.");
    }
    ssdp_stop(); // stop SSDP when disconnected
}

int main()
{

    // initialze mosquitto broker
    struct mosquitto *mosq;
    int rc;
    mosquitto_lib_init();

    mosq = mosquitto_new(NULL, true, NULL);
    if (mosq == NULL)
    {
        perror("Failed to create mosquitto instance");

        return 1;
    }
    mosquitto_connect_callback_set(mosq, on_connect);
    mosquitto_message_callback_set(mosq, on_message);
    mosquitto_publish_callback_set(mosq, on_publish);
    mosquitto_disconnect_callback_set(mosq, on_disconnect);

    // connect to broker
    while (1)
    {
        rc = mosquitto_connect(mosq, "localhost", MQTTPORT, 60);
        if (rc == MOSQ_ERR_SUCCESS)
        {
            puts("Connected to mosquitto broker");
            break;
        }
        perror("Failed to connect to broker, retrying in 5 seconds...");
        sleep(5);
    }

    ssdp_start(); // start SSDP

    mosquitto_loop_forever(mosq, -1, 1);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    return 0;
}
