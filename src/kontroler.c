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
#include <netdb.h>
#include <cjson/cJSON.h>

#define MQTTPORT 1883
#define SSDPPORT 1900
#define HTTPPORT 8080
#define SSDP_ADDR "239.255.255.250"

#define MAX_DEVICES 8
// array of devices
cJSON *device_info[MAX_DEVICES];
cJSON *device_status[MAX_DEVICES];
// Global device information
const char *ssdp_usn = "Kontroler";
const char *ssdp_nts = "device:alive";
const char *ssdp_st = "ssdp:projekat";
const char *ssdp_location = "None"; // or idk
// Global control variable
static volatile int running = 1;
// Thresholds
int vibration_warning_threshold = 10;
int vibration_alert_threshold = 20;
int tilt_warning_threshold = 0.25;
int tilt_alert_threshold = 0.5;
char *state = "OK";

// Function prototypes 
void remove_device_by_id(const char *id);
void send_ssdp_message(int sockfd, struct sockaddr_in *dest_addr, const char *type);
int fetch_json_from_url(const char *url, char *json_buffer, size_t buffer_size);
const char *get_device_id(cJSON *device_json);
void send_ssdp_message(int sockfd, struct sockaddr_in *dest_addr, const char *type);
int fetch_json_from_url(const char *url, char *json_buffer, size_t buffer_size);
const char *get_device_id(cJSON *device_json);




void *multicast_listener(void *arg)
{
    struct mosquitto *mosq = (struct mosquitto *)arg; // Cast argument to mosquitto pointer
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
               char location_url[256];
               char device_id[64];

                //   if (strstr(msgbuf, "USN") != NULL){ // TODO  select only the devices with names
                //  printf("Received from %s:\n%s\n", inet_ntoa(sender_addr.sin_addr), msgbuf); print address
                if (strstr(msgbuf, "NOTIFY") != NULL)
                {
                    if (strstr(msgbuf, "NT: ssdp:projekat") != NULL && strstr(msgbuf, "NTS: ssdp:alive") != NULL)
                    {
                        printf("ALIVE received: %s", msgbuf);
                        char json_buffer[2048];
                        sscanf(strstr(msgbuf, "LOCATION: "), "LOCATION: %[^\r\n]", location_url);
                        if (strcmp(location_url, "None") != 0) {
                            if (fetch_json_from_url(location_url, json_buffer, sizeof(json_buffer)) == 0) {
                                cJSON *json = cJSON_Parse(json_buffer);
                                if (json) {
                                        // Check if device is already connected
                                        const char *new_id = get_device_id(json);
                                        int already_connected = 0;
                                        for (int i = 0; i < MAX_DEVICES; ++i) {
                                            if (device_info[i] != NULL) {
                                                const char *existing_id = get_device_id(device_info[i]);
                                                if (existing_id && strcmp(existing_id, new_id) == 0) {
                                                    already_connected = 1;
                                                    break;
                                                }
                                            }
                                        }
                                        if (!already_connected) {
                                    // Store in device_info array (find a free slot)
                                    for (int i = 0; i < MAX_DEVICES; ++i) {
                                        if (device_info[i] == NULL) {
                                            device_info[i] = json;
                                            printf("Added device: %s\n", get_device_id(json));

                                            // Notify via MQTT
                                            char topic[128];
                                            snprintf(topic, sizeof(topic), "VibeCheck/%s/connected", get_device_id(json));
                                            int ret = mosquitto_publish(mosq, NULL, topic, 0, 0, 0, false);
                                            if (ret != MOSQ_ERR_SUCCESS) {
                                                fprintf(stderr, "Failed to publish: %s\n", mosquitto_strerror(ret));
                                            } else {
                                                printf("Sent device online notification for device!\n\n");
                                            }
                                            break;
                                        }
                                    }
                                        } else {
                                            printf("Device type %s already connected, skipping.\n", new_id);
                                            cJSON_Delete(json); // Free unused json
                                            
                                            }
                                }
                            }
                        }
                        // mosquitto_publish(mosq, NULL, "VibeCheck/control/status", strlen("connected"), "connected", 0, false);
                    }
                    if (strstr(msgbuf, "NT: ssdp:projekat") != NULL && strstr(msgbuf, "NTS: ssdp:byebye") != NULL)
                    {
                        printf("BYEBYE received: %s", msgbuf);
                        sscanf(strstr(msgbuf, "USN: "), "USN: %63[^\r\n]", device_id);
                        remove_device_by_id(device_id);
                        
                    }
                }
                else if (strstr(msgbuf, "HTTP/1.1 200 OK") != NULL && strstr(msgbuf, "ST: ssdp:projekat\r\n") != NULL)
                {
                    printf("RESPONSE received: %s", msgbuf);
                    char json_buffer[2048];
                    sscanf(strstr(msgbuf, "LOCATION: "), "LOCATION: %[^\r\n]", location_url);
                    if (strcmp(location_url, "None") != 0) {
                        if (fetch_json_from_url(location_url, json_buffer, sizeof(json_buffer)) == 0) {
                            cJSON *json = cJSON_Parse(json_buffer);
                            if (json) {
                                
                                // Check if device is already connected
                                const char *new_id = get_device_id(json);
                                int already_connected = 0;
                                for (int i = 0; i < MAX_DEVICES; ++i) {
                                    if (device_info[i] != NULL) {
                                        const char *existing_id = get_device_id(device_info[i]);
                                        if (existing_id && strcmp(existing_id, new_id) == 0) {
                                            already_connected = 1;
                                            break;
                                        }
                                    }
                                }

                                if (!already_connected) {
                                // Store in device_info array (find a free slot)
                                for (int i = 0; i < MAX_DEVICES; ++i) {
                                    if (device_info[i] == NULL) {
                                        device_info[i] = json;
                                        printf("Added device: %s\n", get_device_id(json));
                                        
                                         // Notify via MQTT
                                        char topic[128];
                                        snprintf(topic, sizeof(topic), "VibeCheck/%s/connected", get_device_id(json));
                                        int ret = mosquitto_publish(mosq, NULL, topic, 0, 0, 0, false);
                                        if (ret != MOSQ_ERR_SUCCESS) {
                                            fprintf(stderr, "Failed to publish: %s\n", mosquitto_strerror(ret));
                                        } else {
                                            printf("Sent device online notification for device!\n\n"); //TODO terminate second instance of device
                                        }
                                        break;
                                    }
                                }
                            } else {
                                    printf("Device type %s already connected, skipping.\n", new_id);
                                    cJSON_Delete(json); // Free unused json
                                    
                                    }
                                }
                        }
                        // mosquitto_publish(mosq, NULL, "VibeCheck/control/status", strlen("connected"), "connected", 0, false);
                    }
                    //  }
                }  
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
void ssdp_start(struct mosquitto *mosq)
{
    pthread_t ssdp_thread;
    running = 1;
    pthread_create(&ssdp_thread, NULL, multicast_listener, mosq);
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

int fetch_json_from_url(const char *url, char *json_buffer, size_t buffer_size) {
    // Example: "http://127.0.0.1:8080/sirena.json"
    const char *ip_start;
    const char *ip_end;
    const char *port_start;
    const char *port_end;

    // Find "://"
    ip_start = strstr(url, "://");
    if (!ip_start) return -1;
    ip_start += 3; // move past "://"

    // Find ':'
    ip_end = strchr(ip_start, ':');
    if (!ip_end) return -1;

    // Extract host
    char host[128];
    size_t host_len = ip_end - ip_start;
    if (host_len >= sizeof(host)) return -1;
    strncpy(host, ip_start, host_len);
    host[host_len] = '\0';

    // Find port start and end
    port_start = ip_end + 1;
    port_end = strchr(port_start, '/');
    if (!port_end) return -1;

    // Extract port
    char port_str[8];
    size_t port_len = port_end - port_start;
    if (port_len >= sizeof(port_str)) return -1;
    strncpy(port_str, port_start, port_len);
    port_str[port_len] = '\0';
    int port = atoi(port_str);
    if (port <= 0) return -1;

    // Path starts after '/'
    const char *path = port_end + 1;
    if (!path) return -1;

    //  path points to "sirena.json" or whatever
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char request[256];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    server = gethostbyname(host);
    if (!server) { close(sockfd); return -1; }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sockfd); return -1;
    }
        // Send HTTP GET request
    snprintf(request, sizeof(request),
        "GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
    send(sockfd, request, strlen(request), 0);

    int total = 0, n;
    while ((n = recv(sockfd, json_buffer + total, buffer_size - total - 1, 0)) > 0) {
        total += n;
        if (total >= buffer_size - 1) break;
    }
    json_buffer[total] = '\0';
    close(sockfd);

    // Find start of JSON in HTTP response
    char *json_start = strchr(json_buffer, '{');
    if (!json_start) return -1;
    memmove(json_buffer, json_start, strlen(json_start) + 1); // kao memcopy ali bez overlap problema
    return 0;
}

const char *get_device_id(cJSON *device_json) {
    cJSON *id_item = cJSON_GetObjectItem(device_json, "id");
    return cJSON_IsString(id_item) ? id_item->valuestring : NULL;
}

void remove_device_by_id(const char *id) {
    for (int i = 0; i < MAX_DEVICES; ++i) {
        if (device_info[i] != NULL) {
            const char *dev_id = get_device_id(device_info[i]);
            if (dev_id && strcmp(dev_id, id) == 0) {
                cJSON_Delete(device_info[i]);
                device_info[i] = NULL;
                printf("Removed device: %s\n", id);
                break;
            }
        }
    }

}

char *make_status_json(const char *type, float number, const char *state) {
    cJSON *root = cJSON_CreateObject();
    if (strcmp(type, "vibration") == 0) {
        cJSON_AddNumberToObject(root, "vibration", number);
    } else if (strcmp(type, "tilt") == 0) {
        cJSON_AddNumberToObject(root, "tilt", number);
    } else {
        cJSON_AddStringToObject(root, "error", "unknown type");
        cJSON_AddNumberToObject(root, "error_value", number);
    }
    cJSON_AddStringToObject(root, "state", state);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str; // TODO always fre  with cJSON_free() after publishing
}


void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
    if (rc == 0)
    {
        puts("Subscribing to topics...");
        mosquitto_subscribe(mosq, NULL, "VibeCheck/sensors/vibration", 0);
        mosquitto_subscribe(mosq, NULL, "VibeCheck/sensors/tilt", 0);
        mosquitto_subscribe(mosq, NULL, "VibeCheck/threshold/change", 0);
        mosquitto_subscribe(mosq, NULL, "VibeCheck/+/disconnected", 0);

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
    // Handle messages based on topic
    if(strcmp(msg->topic, "VibeCheck/sensors/vibration") == 0) {
        // Handle vibration sensor data
        printf("Vibration sensor data received: %s\n", (char *)msg->payload);
        int vibration = atoi((char *)msg->payload);
        const char *sirena_msg = "OFF";
        const char *led_msg = "OFF";
        else if (vibration >= vibration_alert_threshold) {
            sirena_msg = "STEADY";
            led_msg = "FAST";
            state = "ALERT";

        } else if (vibration >= vibration_warning_threshold) {
            if (strcmp(state, "ALERT") != 0){
                 sirena_msg = "INTERMITTENT";
                 led_msg = "SLOW";
                 state = "WARNING";
                }
         
        }

        // Publish to sirena
        int ret1 = mosquitto_publish(mosq, NULL, "VibeCheck/acct/control", strlen(sirena_msg), sirena_msg, 0, false);
        if (ret1 != MOSQ_ERR_SUCCESS) {
            fprintf(stderr, "Failed to publish to sirena: %s\n", mosquitto_strerror(ret1));
        } else {
            printf("Published to sirena: %s\n", sirena_msg);
        }
        // Publish to LEDd 
        int ret2 = mosquitto_publish(mosq, NULL, "VibeCheck/actuators/LED", strlen(led_msg), led_msg, 0, false);
        if (ret2 != MOSQ_ERR_SUCCESS) {
            fprintf(stderr, "Failed to publish to LED: %s\n", mosquitto_strerror(ret2));
        } else {
            printf("Published to LED: %s\n", led_msg);
        }
        // Publish status JSON
        char *json_str = make_status_json("vibration", vibration, state);
        mosquitto_publish(mosq, NULL, "VibeCheck/status", strlen(json_str), json_str, 0, false);
        cJSON_free(json_str);   

    } else if(strcmp(msg->topic, "VibeCheck/sensors/tilt") == 0) {
        // Handle tilt sensor data
        printf("Tilt sensor data received: %s\n", (char *)msg->payload);
    } else if(strcmp(msg->topic, "VibeCheck/threshold/change") == 0) {
        // Handle threshold change command
        printf("Threshold change command received: %s\n", (char *)msg->payload);
    } else if(strstr(msg->topic, "/disconnected") != NULL) {
        // Handle device disconnection
        char device_id[64];
        if (sscanf(msg->topic, "VibeCheck/%63[^/]/disconnected", device_id) == 1) {
            // device_id contains the ID
            remove_device_by_id(device_id);
        }
        printf("Device disconnected: %s\n", (char *)msg->payload);

    }
    
}

void on_publish(struct mosquitto *mosq, void *obj, int mid)
{
    printf("Message -> %d <- has been published to %s.\n", mid, (char *)obj);
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

    ssdp_start(mosq); // start SSDP

    mosquitto_loop_forever(mosq, -1, 1);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    return 0;
}
