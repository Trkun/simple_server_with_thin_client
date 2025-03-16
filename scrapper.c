#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 8192
#define BIG_BUFFER_SIZE 16384  // assume a large buffer size for formatting requests to avoid buffer overflow

// Connect to server
int connect_to_server(const char *host, const char *port) {
    struct addrinfo hints, *res, *p;
    int sockfd = -1, rv;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    if((rv = getaddrinfo(host, port, &hints, &res)) != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }
    
    for(p = res; p != NULL; p = p->ai_next) {
        if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
            continue;
        if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            sockfd = -1;
            continue;
        }
        break;
    }
    freeaddrinfo(res);
    if(sockfd == -1)
        printf("Failed to connect to %s:%s\n", host, port);
    return sockfd;
}

// Send all data.
void send_all(int sockfd, const char *data, size_t len) {
    size_t total = 0;
    ssize_t n;
    while(total < len) {
        n = send(sockfd, data + total, len - total, 0);
        if(n <= 0) break;
        total += n;
    }
}

// Read full response from socket.
char *read_response(int sockfd) {
    size_t bufsize = BUFFER_SIZE;
    char *response = malloc(bufsize);
    if(!response) { perror("malloc"); exit(1); }
    size_t total = 0;
    ssize_t n;
    while((n = recv(sockfd, response + total, bufsize - total - 1, 0)) > 0) {
        total += n;
        if(total > bufsize - 100) {
            bufsize *= 2;
            char *tmp = realloc(response, bufsize);
            if(!tmp) { perror("realloc"); free(response); exit(1); }
            response = tmp;
        }
    }
    response[total] = '\0';
    return response;
}

// Read file content into memory.
char *read_file(const char *filename, size_t *size_out) {
    FILE *f = fopen(filename, "rb");
    if(!f) { printf("Failed to open file %s\n", filename); return NULL; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    char *data = malloc(size + 1);
    if(!data) { printf("malloc error\n"); fclose(f); return NULL; }
    size_t bytes_read = fread(data, 1, size, f);
    if(bytes_read != (size_t)size)
        printf("Warning: expected %ld bytes, but read %zu bytes\n", size, bytes_read);
    data[size] = '\0';
    fclose(f);
    *size_out = bytes_read;
    return data;
}

// Extract the session cookie from the response header.
char *extract_cookie(const char *response) {
    const char *set_cookie = "Set-Cookie:";
    char *start = strstr(response, set_cookie);
    if(!start) return NULL;
    start += strlen(set_cookie);
    while(*start == ' ') start++;
    char *end = strchr(start, ';');
    if(!end) end = start + strlen(start);
    size_t len = end - start;
    char *cookie = malloc(len + 1);
    if(!cookie) return NULL;
    strncpy(cookie, start, len);
    cookie[len] = '\0';
    return cookie;
}

void perform_test(const char *host, const char *port, const char *username, const char *push_filename) {
    int sock;
    char request[BIG_BUFFER_SIZE];
    char *response;
    char *session_cookie = NULL;

    // Test unauthenticated GET /api/list.
    printf("Testing unauthenticated GET /api/list...\n");
    sock = connect_to_server(host, port);
    assert(sock != -1);
    snprintf(request, sizeof(request),
             "GET /api/list HTTP/1.1\r\nHost: %s\r\n\r\n", host);
    send_all(sock, request, strlen(request));
    response = read_response(sock);
    close(sock);
    if (!(response && (strstr(response, "401") || strstr(response, "Not logged in")))) {
        printf("Error: Unauthenticated GET /api/list did not return expected error.\n");
        exit(1);
    }
    printf("Unauthenticated GET /api/list correctly returned error.\n");
    free(response);

    // Login.
    printf("Logging in as '%s'...\n", username);
    sock = connect_to_server(host, port);
    assert(sock != -1);
    char login_body[256];
    snprintf(login_body, sizeof(login_body), "%s", username);
    snprintf(request, sizeof(request),
             "POST /api/login HTTP/1.1\r\nHost: %s\r\nContent-Length: %zu\r\nContent-Type: text/plain\r\n\r\n%s",
             host, strlen(login_body), login_body);
    send_all(sock, request, strlen(request));
    response = read_response(sock);
    if (!(response && strstr(response, "Logged in as"))) {
        printf("Login failed. Response: %s\n", response ? response : "NULL");
        exit(1);
    }
    session_cookie = extract_cookie(response);
    if (!session_cookie) {
        printf("Failed to extract session cookie.\n");
        exit(1);
    }
    printf("Logged in successfully. Session cookie: %s\n", session_cookie);
    free(response);
    close(sock);

    // Check that file is not in list.
    printf("Checking that file '%s' is not present...\n", push_filename);
    sock = connect_to_server(host, port);
    assert(sock != -1);
    snprintf(request, sizeof(request),
             "GET /api/list HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\n\r\n", host, session_cookie);
    send_all(sock, request, strlen(request));
    response = read_response(sock);
    if (response && strstr(response, push_filename)) {
        printf("Error: File '%s' already exists before upload.\n", push_filename);
        exit(1);
    }
    printf("No duplicate file found.\n");
    free(response);
    close(sock);

    // Upload the file.
    printf("Uploading file '%s'...\n", push_filename);
    size_t file_size;
    char *file_content = read_file(push_filename, &file_size);
    assert(file_content != NULL);
    sock = connect_to_server(host, port);
    assert(sock != -1);
    char push_url[256];
    snprintf(push_url, sizeof(push_url), "/api/push?file=%s", push_filename);
    snprintf(request, sizeof(request),
             "POST %s HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nContent-Length: %zu\r\nContent-Type: text/plain\r\n\r\n",
             push_url, host, session_cookie, file_size);
    send_all(sock, request, strlen(request));
    send_all(sock, file_content, file_size);
    response = read_response(sock);
    if (!(response && strstr(response, "uploaded"))) {
        printf("Upload failed. Response: %s\n", response ? response : "NULL");
        exit(1);
    }
    printf("File '%s' uploaded successfully.\n", push_filename);
    free(response);
    close(sock);
    free(file_content);

    // Verify file appears in list.
    printf("Verifying file '%s' is now in the list...\n", push_filename);
    sock = connect_to_server(host, port);
    assert(sock != -1);
    snprintf(request, sizeof(request),
             "GET /api/list HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\n\r\n", host, session_cookie);
    send_all(sock, request, strlen(request));
    response = read_response(sock);
    if (!(response && strstr(response, push_filename))) {
        printf("Error: File '%s' not found in list after upload.\n", push_filename);
        exit(1);
    }
    printf("File '%s' is present in the file list.\n", push_filename);
    free(response);
    close(sock);

    free(session_cookie);
    printf("Test end without core dumped :p.\n");
}

int main(int argc, char *argv[]) {
    if(argc != 5) {
        printf("Usage: %s [host] [port] [username] [file_to_push]\n", argv[0]);
        return 1;
    }
    perform_test(argv[1], argv[2], argv[3], argv[4]);
    return 0;
}
