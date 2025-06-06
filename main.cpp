#include <pcap.h>
#include <iostream>
#include <fstream>
#include <csignal>
#include <vector>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string>
#include <iomanip>

std::ofstream output_file;
char *filename = nullptr;
char *filter = nullptr;
bpf_program fp;
int matched_packets = 0;
int dropped_packets = 0;
pcap_t *handle;

void handle_sigint(int sig)
{
    if (sig == SIGINT)
    {
        if (handle)
        {
            struct pcap_stat ps;
            pcap_stats(handle, &ps);
            dropped_packets = (&ps)->ps_drop;
            pcap_close(handle);
        }
        if (output_file.is_open())
        {
            output_file.close();
        }
        std::cout << "\rЗахват пакетов остановлен. Принято: " << matched_packets << ". Отброшено: " << dropped_packets << "\n";
        std::cout << "Сохранено в файл " << filename << "\n\n\n";
        pcap_freecode(&fp);
        exit(0);
    }
}

void print_packet_int(const int len, const u_char *packet)
{
    for (int i = 0; i < len; ++i)
    {
        output_file << std::setw(2) << std::hex << (int)packet[i] << " ";
        if ((i + 1) % 16 == 0)
            output_file << "\n";
    }
}

void print_packet_char(const int len, const u_char *packet)
{
    for (int i = 0; i < len; ++i)
    {
        if (packet[i] < 128 && packet[i] > 32)
            output_file << std::setw(2) << packet[i] << " ";
        else
            output_file << ".." << " ";

        if ((i + 1) % 16 == 0)
            output_file << "\n";
    }
}

void get_packet_info(const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
        return;

    const struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

    std::string src_ip = inet_ntoa(ip_hdr->ip_src);
    std::string dst_ip = inet_ntoa(ip_hdr->ip_dst);
    u_int8_t protocol = ip_hdr->ip_p;

    output_file << "Протокол: ";
    switch (protocol)
    {
    case IPPROTO_TCP:
        output_file << "TCP";
        break;
    case IPPROTO_UDP:
        output_file << "UDP";
        break;
    case IPPROTO_ICMP:
        output_file << "ICMP";
        break;
    default:
        output_file << "Неизвестный";
    }

    output_file << " | Src IP: " << src_ip << " | Dst IP: " << dst_ip;

    if (protocol == IPPROTO_TCP)
    {
        const struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_hdr->ip_hl * 4);
        output_file << " | Src Port: " << ntohs(tcp_hdr->th_sport)
                  << " | Dst Port: " << ntohs(tcp_hdr->th_dport);
    }
    else if (protocol == IPPROTO_UDP)
    {
        const struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_hdr->ip_hl * 4);
        output_file << " | Src Port: " << ntohs(udp_hdr->uh_sport)
                  << " | Dst Port: " << ntohs(udp_hdr->uh_dport);
    }

    output_file << "\n\n";
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    matched_packets++;
    std::cout << "Найден подходящий пакет " << matched_packets << "\n";
    output_file << "\nПакет " << std::dec << matched_packets << "\n";
    output_file << "Размер пакета: " << header->len << " байт \n";
    get_packet_info(header, packet);
    print_packet_int(header->len, packet);
    output_file << "\n\n";
    print_packet_char(header->len, packet);
    output_file << "\n\n";
}

int check_args(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "Укажите BPF выражение\n";
        return 1;
    }

    filter = argv[1];
    filename = (argc > 2) ? argv[2] : (char *)"save.txt";
    return 0;
}

std::string pick_interface()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    std::vector<std::string> device_names;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Не найдены сетевые интерфейсы: " << errbuf << "\n";
        return "";
    }

    std::cout << "Доступные интерфейсы:\n";
    int i = 0;
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next)
    {
        std::cout << ++i << ". " << (d->name ? d->name : "Неизвестный") << " - "
                  << (d->description ? d->description : "Без описания") << "\n";
        device_names.push_back(d->name);
    }

    if (device_names.empty())
    {
        std::cerr << "Нет доступных интерфейсов для захвата.\n";
        return "";
    }

    int choice;
    std::cout << "Выберите интерфейс (введите номер): ";
    std::cin >> choice;

    if (choice < 1 || choice > (int)device_names.size())
    {
        std::cerr << "Неверный выбор интерфейса.\n";
        return nullptr;
    }
    pcap_freealldevs(alldevs);
    return device_names[choice - 1];
}

int set_bpf_filter(bpf_u_int32 net)
{

    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    {
        std::cerr << "Ошибка компиляции фильтра: " << pcap_geterr(handle) << "\n";
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        std::cerr << "Ошибка установки фильтра: " << pcap_geterr(handle) << "\n";
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (check_args(argc, argv) != 0)
        return 1;

    char errbuf[PCAP_ERRBUF_SIZE];
    std::string dev = pick_interface();
    if (dev.empty())
        return 1;

    handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        std::cerr << "Не удалось открыть сетевой интерфейс: " << errbuf << "\n";
        return 1;
    }

    bpf_u_int32 net, mask;
    if (pcap_lookupnet(dev.c_str(), &net, &mask, errbuf) == -1)
    {
        net = 0;
        mask = 0;
    }
    else
        std::cout << "Сеть: " << net << " Маска: " << mask << "\n";

    if (set_bpf_filter(net) != 0)
        return 1;

    output_file.open(filename, std::ios::out);
    if (!output_file.is_open())
    {
        std::cerr << "Не удалось открыть файл для записи\n";
        return 8;
    }

    signal(SIGINT, handle_sigint);
    std::cout << "Начинаем захват пакетов на интерфейсе " << dev << "...\n";

    pcap_loop(handle, 0, packet_handler, nullptr);

    output_file.close();
    pcap_close(handle);
    return 0;
}