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
#include <cjson/cJSON.h>

#define MQTTPORT 1883
#define SSDPPORT 1900
#define SSDP_ADDR "239.255.255.250"


#define MAX_DEVICES 8
#define MAX_ID_LEN 64

double currentVibration = 0.0;
double currentTilt = 0.0;
//char currentStateSystem[64] = "OK";
char currentStateVibration[64] = "OK";
char currentStateTilt[64] = "OK";
double VibrationWarningThreshold = 10.0;
double VibrationAlertThreshold = 20.0;
double TiltWarningThreshold = 0.25;
double TiltAlertThreshold = 0.5;
// Global device information
const char *ssdp_nt = "device:alive";
const char *ssdp_usn = "Application";
const char *ssdp_location = "None"; // or idk
// Global control variable
static volatile int running = 1;

char device_ids[MAX_DEVICES][MAX_ID_LEN];
int device_count = 0;

// Function prototype
void send_ssdp_message(int sockfd, struct sockaddr_in *dest_addr, const char *type);
void print_status();

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
    printf("Multicast listener started on 239.255.255.250:%d\n\n", SSDPPORT);

    // Make socket non-blocking
    int flags = fcntl(ssdp_sockfd, F_GETFL, 0);
    fcntl(ssdp_sockfd, F_SETFL, flags | O_NONBLOCK);

    // Send initial alive announcement
    send_ssdp_message(ssdp_sockfd, NULL, "alive"); // send alive on start to everzyone

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

                if (strstr(msgbuf, "M-SEARCH") != NULL)
                {

                    if (strstr(msgbuf, "ST:ssdp:projekat\r\n") != NULL)
                    { // TODO  select only the devices needed for project
                        printf("M-SEARCH received: %s\n", msgbuf);
                        send_ssdp_message(ssdp_sockfd, &sender_addr, "response");
                    }
                }
            }
        }
    }
    // Send byebye announcement before exiting
    printf("Shutting down SSDP. Sending byebye...\n");
    send_ssdp_message(ssdp_sockfd, NULL, "byebye");

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
    if (strcmp(type, "alive") == 0)
    {
        snprintf(message, sizeof(message),
                 "NOTIFY * HTTP/1.1\r\n"
                 "HOST: %s:%d\r\n"
                 "NT:%s\r\n"          // type
                 "NTS:ssdp:alive\r\n" // subtype
                 "USN:%s\r\n"         // unique name
                 "LOCATION:%s\r\n"
                 "\r\n",
                 SSDP_ADDR, SSDPPORT, ssdp_nt, ssdp_usn, ssdp_location);
    }
    else if (strcmp(type, "byebye") == 0)
    {
        snprintf(message, sizeof(message),
                 "NOTIFY * HTTP/1.1\r\n"
                 "HOST: %s:%d\r\n"
                 "NT:%s\r\n"           // type
                 "NTS:ssdp:byebye\r\n" // subtype
                 "USN:%s\r\n"          // unique name
                 "\r\n",
                 SSDP_ADDR, SSDPPORT, ssdp_nt, ssdp_usn);
    }
    else if (strcmp(type, "response") == 0)
    {
        snprintf(message, sizeof(message),
                 "HTTP/1.1 200 OK\r\n"
                 "CACHE-CONTROL: max-age=1800\r\n"
                 //"DATE: \r\n"
                 //"EXT:\r\n"
                 "LOCATION:%s\r\n"
                 "ST:%s\r\n"
                 "USN:%s\r\n"
                 "\r\n",
                 ssdp_location, ssdp_nt, ssdp_usn);
    }
    else
    {
        fprintf(stderr, "Unknown SSDP message type: %s\n", type);
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
        mosquitto_subscribe(mosq, NULL, "VibeCheck/app/vibration", 0);
        mosquitto_subscribe(mosq, NULL, "VibeCheck/app/tilt", 0);
        mosquitto_subscribe(mosq, NULL, "VibeCheck/app/devices", 0);
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
    if (strcmp(msg->topic, "VibeCheck/app/vibration") == 0) {
        cJSON *root = cJSON_Parse((char *)msg->payload);
        if (root) {
            cJSON *vib_item = cJSON_GetObjectItem(root, "vibration");
            cJSON *state_item = cJSON_GetObjectItem(root, "state");
            if (cJSON_IsNumber(vib_item)) {
                currentVibration = vib_item->valuedouble;
            }
            if (cJSON_IsString(state_item)) {
                strncpy(currentStateVibration, state_item->valuestring, sizeof(currentStateVibration)-1);
                currentStateVibration[sizeof(currentStateVibration)-1] = '\0';
            }
            cJSON_Delete(root);
        }
    } else if (strcmp(msg->topic, "VibeCheck/app/tilt") == 0) {
        cJSON *root = cJSON_Parse((char *)msg->payload);
        if (root) {
            cJSON *tilt_item = cJSON_GetObjectItem(root, "tilt");
            cJSON *state_item = cJSON_GetObjectItem(root, "state");
            if (cJSON_IsNumber(tilt_item)) {
                currentTilt = tilt_item->valuedouble;
            }
            if (cJSON_IsString(state_item)) {
                strncpy(currentStateTilt, state_item->valuestring, sizeof(currentStateTilt)-1);
                currentStateTilt[sizeof(currentStateTilt)-1] = '\0';
            }
            cJSON_Delete(root);
        }
    } else if (strcmp(msg->topic, "VibeCheck/app/devices") == 0) {
        cJSON *root = cJSON_Parse((char *)msg->payload);
        if (root && cJSON_IsArray(root)) {
            // Clear old list
            device_count = 0;
            // Parse new list
            int arr_size = cJSON_GetArraySize(root);
            for (int i = 0; i < arr_size && i < MAX_DEVICES; ++i) {
                cJSON *item = cJSON_GetArrayItem(root, i);
                if (cJSON_IsString(item)) {
                    strncpy(device_ids[device_count], item->valuestring, MAX_ID_LEN-1);
                    device_ids[device_count][MAX_ID_LEN-1] = '\0';
                    device_count++;
                }
            }
            cJSON_Delete(root);
        } else if (root) {
            cJSON_Delete(root);
        }
    }
    print_status();
}

void print_status()
{
    puts("----- Current Status -----");
    printf("Current Vibration: %.2f\n", currentVibration);
    printf("Current Tilt: %.2f\n", currentTilt);
    printf("Current State (Vibration): %s\n", currentStateVibration);
    printf("Current State (Tilt): %s\n", currentStateTilt);
    printf("Vibration Thresholds: Warning=%.2f, Alert=%.2f\n", VibrationWarningThreshold, VibrationAlertThreshold);
    printf("Tilt Thresholds: Warning=%.2f, Alert=%.2f\n", TiltWarningThreshold, TiltAlertThreshold);
    printf("Online Devices (%d):\n", device_count);
    for (int i = 0; i < device_count; ++i) {
        printf("--> %s\n", device_ids[i]);
    }
    puts("--------------------------\n");
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

    // Connect to broker
    int rc;
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

    mosquitto_loop_start(mosq); // Start MQTT loop in background

    char cmd[256];
    printf("Type threshold change commands:\n");
    printf("  Vibration <warning> <alert>\n");
    printf("  Tilt <warning> <alert>\n");
    printf("Type q to quit...\n");

    while (1)
    {
        if (fgets(cmd, sizeof(cmd), stdin) == NULL)
            break;
        cmd[strcspn(cmd, "\n")] = 0;
        if (strcmp(cmd, "q") == 0 || strcmp(cmd, "Q") == 0)
            break;

        if (strncmp(cmd, "Vibration ", 10) == 0) {
            double warning, alert;
            if (sscanf(cmd + 10, "%lf %lf", &warning, &alert) == 2) {
                if (alert <= warning) {
                    printf("Error: Alert threshold must be greater than warning threshold!\n");
                    continue;   
                }
                VibrationWarningThreshold = warning;
                VibrationAlertThreshold = alert;
                cJSON *json = cJSON_CreateObject();
                cJSON_AddStringToObject(json, "type", "VibrationThresholds");
                cJSON_AddNumberToObject(json, "warning", warning);
                cJSON_AddNumberToObject(json, "alert", alert);
                char *payload = cJSON_PrintUnformatted(json);
                mosquitto_publish(mosq, NULL, "VibeCheck/control/thresholds", strlen(payload), payload, 0, false);
                cJSON_free(payload);
                cJSON_Delete(json);
                printf("Sent Vibration thresholds: warning=%f, alert=%f\n", warning, alert);
                if (warning < VibrationWarningThreshold){
                    strcpy(currentStateVibration, "OK"); // reset state to force update
                }
                if (alert < VibrationAlertThreshold){
                    strcpy(currentStateVibration, "OK"); // reset state to force update
                }
            } else {
                printf("Invalid command format! Use: Vibration <warning> <alert> with space in between\n");
            }
        } else if (strncmp(cmd, "Tilt ", 5) == 0) {
            double warning, alert;
            if (sscanf(cmd + 5, "%lf %lf", &warning, &alert) == 2) {
                if (alert <= warning) {
                    printf("Error: Alert threshold must be greater than warning threshold!\n");
                    continue;
                }
                TiltWarningThreshold = warning;
                TiltAlertThreshold = alert;
                cJSON *json = cJSON_CreateObject();
                cJSON_AddStringToObject(json, "type", "TiltThresholds");
                cJSON_AddNumberToObject(json, "warning", warning);
                cJSON_AddNumberToObject(json, "alert", alert);
                char *payload = cJSON_PrintUnformatted(json);
                mosquitto_publish(mosq, NULL, "VibeCheck/control/thresholds", strlen(payload), payload, 0, false);
                cJSON_free(payload);
                cJSON_Delete(json);
                printf("Sent Tilt thresholds: warning=%f, alert=%f\n", warning, alert);
                if (warning < TiltWarningThreshold){
                    strcpy(currentStateTilt, "OK"); // reset state to force update
                }
                if (alert < TiltAlertThreshold){
                    strcpy(currentStateTilt, "OK"); // reset state to force update
                }
            } else {
                printf("Invalid command format! Use: Tilt <warning> <alert> with space in between\n");
            }
        } else if (strncmp(cmd, "SIRENA ", 7) == 0) {
            char value[32];
            if (sscanf(cmd + 7, "%31s", value) == 1) {
                if (strcmp(value, "OFF") == 0 || strcmp(value, "WARNING") == 0 || strcmp(value, "ALERT") == 0) {
                    cJSON *json = cJSON_CreateObject();
                    cJSON_AddStringToObject(json, "SIRENA", value);
                    char *payload = cJSON_PrintUnformatted(json);
                    mosquitto_publish(mosq, NULL, "VibeCheck/control/command", strlen(payload), payload, 0, false);
                    printf("Sent SIRENA command: %s\n\n", payload);
                    cJSON_free(payload);
                    cJSON_Delete(json);
                } else {
                    printf("Invalid value! Use OFF, WARNING, or ALERT\n");
                }
            } 
        } else if (strncmp(cmd, "LED ", 4) == 0) {
            char value[32];
            if (sscanf(cmd + 4, "%31s", value) == 1) {
                if (strcmp(value, "OFF") == 0 || strcmp(value, "WARNING") == 0 || strcmp(value, "ALERT") == 0) {
                    cJSON *json = cJSON_CreateObject();
                    cJSON_AddStringToObject(json, "LED", value);
                    char *payload = cJSON_PrintUnformatted(json);
                    mosquitto_publish(mosq, NULL, "VibeCheck/control/command", strlen(payload), payload, 0, false);
                    printf("Sent LED command: %s\n\n", payload);
                    cJSON_free(payload);
                    cJSON_Delete(json);
                } else {
                    printf("Invalid value! Use OFF, WARNING, or ALERT\n");
                }
            } 
        } else {
            printf("Unknown command. Command list: \n");
            printf(" Threshold change:\n");
            printf("    Vibration <warning> <alert>\n");
            printf("    Tilt <warning> <alert>\n");
            printf(" Actuator control:\n");
            printf("    SIRENA <OFF|WARNING|ALERT>\n");
            printf("    LED <OFF|WARNING|ALERT>\n\n");
        }
    }

    mosquitto_loop_stop(mosq, true);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();

    return 0;
}
