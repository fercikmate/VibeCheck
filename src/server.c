#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 8080
#define BUFFER_SIZE 2048
#define DESCRIPTIONS_DIR "./ServerDeviceDescriptions"

// Read file
int read_file(const char *filename, char **buffer) {
    FILE *file = fopen(filename, "r");  // Simple read mode
    if (!file) return -1; // File not found

    fseek(file, 0, SEEK_END);
    long size = ftell(file); 
    fseek(file, 0, SEEK_SET); //back to start
    

    *buffer = malloc(size + 1); // +1 for /0
    fread(*buffer, 1, size, file);
    fclose(file);
    
    (*buffer)[size] = '\0';
    return size;
}

// Send HTTP response
void send_response(int client_socket, const char *status, const char *body, int content_length) {
    char header[512];
    snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, content_length);
    
    send(client_socket, header, strlen(header), 0); // header first
    send(client_socket, body, content_length, 0); // body -JSON-
    //npr "{\n  \"id\": \"vibration_sensor_1\",\n  \"group\": \"sensor\"\n}"
}

int main() {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    printf("Starting HTTP Server on port %d\n", PORT);
    
    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket failed");
        return 1;
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Bind
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }
    
    // Listen
    if (listen(server_fd, 1) < 0) {  // Only 1 connection at a time
        perror("Listen failed");
        close(server_fd);
        return 1;
    }
    
    printf("Serving JSON files from: %s/\n", DESCRIPTIONS_DIR);
    printf("Server ready on port %d. Waiting for requests...\n\n",PORT);

    while (1) {
        // Accept connection
        client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        
        // Read HTTP request
        char buffer[BUFFER_SIZE] = {0};
        int bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            
            // get the cmd and to filename
            char cmd[16], filename[256];
            sscanf(buffer, "%s %s", cmd, filename);
            //only using get cmd
            if (strcmp(cmd, "GET") != 0) {
                send_response(client_socket, "405 Method Not Allowed", "Only GET supported", 20);
                close(client_socket);
                continue;
            }
            printf("Request: %s %s\n", cmd, filename);
            // Build file path from descriptions dir and requested file
            char filepath[512];
            strcpy(filepath, DESCRIPTIONS_DIR);
            strcat(filepath, filename);
            
            // Try to read and serve the file
            char *file_content = NULL;
            int file_size = read_file(filepath, &file_content);
            
            if (file_size > 0) {
                send_response(client_socket, "200 OK", file_content, file_size);
                free(file_content);
            } else {
                printf("File not found: %s\n", filepath);
                send_response(client_socket, "404 Not Found", "File not found", strlen("File not found"));
            }
        }
        else {
            perror("Failed to read request");
        }
        
        close(client_socket);
    }
    
    close(server_fd);
    return 0;
}