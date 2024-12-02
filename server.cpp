#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <thread>
#include <mutex>
#include <chrono>

#pragma comment(lib, "Ws2_32.lib")
#define PROXY_PORT 8080
#define BUFFER_SIZE 8192
#define BLOCKED_SITES_FILE "blackList.txt"
#define RELOAD_INTERVAL 30 // Tải lại danh sách chặn sau mỗi 30 giây
std::set<std::string> blockedSites;
std::mutex blockedSitesMutex;

// Hàm tải danh sách chặn từ file
void loadBlockedSites(const std::string& filename) {
    std::set<std::string> newBlockedSites;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Could not open blocked sites file: " << filename << "\n";
        return;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            newBlockedSites.insert(line);
        }
    }
    file.close();
    std::lock_guard<std::mutex> lock(blockedSitesMutex);
    blockedSites = std::move(newBlockedSites);
    std::cout << "Blocked sites reloaded. Total: " << blockedSites.size() << "\n";
}

// Hàm kiểm tra xem một trang web/host có bị chặn không
bool isBlocked(const std::string& hostOrUrl) {
    std::lock_guard<std::mutex> lock(blockedSitesMutex);
    for (const auto& blockedSite : blockedSites) {
        if (hostOrUrl.find(blockedSite) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// Xử lý kết nối của client
void handleClient(SOCKET clientSocket) {
    char buffer[BUFFER_SIZE];
    int recvSize = recv(clientSocket, buffer, BUFFER_SIZE, 0);
    if (recvSize <= 0) {
        closesocket(clientSocket);
        return;
    }

    std::string request(buffer, recvSize);
    std::cout << "Request received:\n" << request << "\n";

    // Tìm Host trong yêu cầu HTTP/HTTPS
    size_t posHost = request.find("Host: ");
    if (posHost == std::string::npos) {
        closesocket(clientSocket);
        return;
    }

    size_t endHost = request.find("\r\n", posHost);
    std::string host = request.substr(posHost + 6, endHost - (posHost + 6));
    std::cout << "Parsed Host: " << host << "\n";

    // Kiểm tra nếu trang web bị chặn
    if (isBlocked(host)) {
        std::string response = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n"
                               "<html><body><h1>403 Forbidden</h1>"
                               "<p>Access to " + host + " is blocked by the proxy server.</p>"
                               "</body></html>";
        send(clientSocket, response.c_str(), response.size(), 0);
        closesocket(clientSocket);
        return;
    }

    // Xử lý HTTPS (CONNECT)
    if (request.find("CONNECT") == 0) {
        size_t posPort = host.find(":");
        std::string hostname = (posPort == std::string::npos) ? host : host.substr(0, posPort);

        struct addrinfo hints = {0}, *serverInfo;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostname.c_str(), "443", &hints, &serverInfo) != 0) {
            closesocket(clientSocket);
            return;
        }

        SOCKET serverSocket = socket(serverInfo->ai_family, serverInfo->ai_socktype, serverInfo->ai_protocol);
        if (connect(serverSocket, serverInfo->ai_addr, (int)serverInfo->ai_addrlen) == SOCKET_ERROR) {
            freeaddrinfo(serverInfo);
            closesocket(clientSocket);
            return;
        }
        freeaddrinfo(serverInfo);

        const char* response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(clientSocket, response, strlen(response), 0);

        std::thread([clientSocket, serverSocket]() {
            char buffer[BUFFER_SIZE];
            int bytesReceived;
            while ((bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0)) > 0) {
                send(serverSocket, buffer, bytesReceived, 0);
            }
            closesocket(serverSocket);
        }).detach();

        std::thread([clientSocket, serverSocket]() {
            char buffer[BUFFER_SIZE];
            int bytesReceived;
            while ((bytesReceived = recv(serverSocket, buffer, BUFFER_SIZE, 0)) > 0) {
                send(clientSocket, buffer, bytesReceived, 0);
            }
            closesocket(clientSocket);
        }).detach();

        return;
    }
    // Xử lý HTTP
    struct addrinfo hints = {0}, *serverInfo;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), "80", &hints, &serverInfo) != 0) {
        closesocket(clientSocket);
        return;
    }
    SOCKET serverSocket = socket(serverInfo->ai_family, serverInfo->ai_socktype, serverInfo->ai_protocol);
    if (connect(serverSocket, serverInfo->ai_addr, (int)serverInfo->ai_addrlen) == SOCKET_ERROR) {
        freeaddrinfo(serverInfo);
        closesocket(clientSocket);
        return;
    }
    freeaddrinfo(serverInfo);
    send(serverSocket, buffer, recvSize, 0);
    std::thread([clientSocket, serverSocket]() {
        char buffer[BUFFER_SIZE];
        int bytesReceived;
        while ((bytesReceived = recv(serverSocket, buffer, BUFFER_SIZE, 0)) > 0) {
            send(clientSocket, buffer, bytesReceived, 0);
        }
        closesocket(serverSocket);
    }).detach();
    std::thread([clientSocket, serverSocket]() {
        char buffer[BUFFER_SIZE];
        int bytesReceived;
        while ((bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0)) > 0) {
            send(serverSocket, buffer, bytesReceived, 0);
        }
        closesocket(clientSocket);
    }).detach();
}
// Luồng tải lại danh sách chặn định kỳ
void reloadBlockedSitesPeriodically() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(RELOAD_INTERVAL));
        loadBlockedSites(BLOCKED_SITES_FILE);
    }
}
int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    loadBlockedSites(BLOCKED_SITES_FILE);
    std::thread(reloadBlockedSitesPeriodically).detach();
    SOCKET proxySocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (proxySocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed\n";
        WSACleanup();
        return 1;
    }
    sockaddr_in proxyAddr = {0};
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_port = htons(PROXY_PORT);
    proxyAddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(proxySocket, (sockaddr*)&proxyAddr, sizeof(proxyAddr)) == SOCKET_ERROR) {
        std::cerr << "Binding failed\n";
        closesocket(proxySocket);
        WSACleanup();
        return 1;
    }
    listen(proxySocket, SOMAXCONN);
    std::cout << "Proxy Server running on port " << PROXY_PORT << "\n";
    while (true) {
        SOCKET clientSocket = accept(proxySocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) {
            continue;
        }
        std::thread(handleClient, clientSocket).detach();
    }
    closesocket(proxySocket);
    WSACleanup();
    return 0;
}

//  g++ server.cpp -o server -lws2_32