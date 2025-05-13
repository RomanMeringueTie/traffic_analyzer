#include <pcap.h>
#include <iostream>
#include <fstream>
#include <csignal>
#include <vector>
#include <string>
#include <iomanip>

std::ofstream output_file;
char *filename = nullptr;
char *filter = nullptr;
int matched_packets = 0;
int dropped_packets = 0;
pcap_t *handle;

void handle_sigint(int sig)
{
    if (sig == SIGINT)
    {
        if (handle)
        {
            struct pcap_stat *ps = new pcap_stat;
            pcap_stats(handle, ps);
            dropped_packets = ps->ps_drop;
            pcap_close(handle);
            delete ps;
        }
        if (output_file.is_open())
        {
            output_file.close();
        }
        std::cout << "\rЗахват пакетов остановлен. Принято: " << matched_packets << ". Отброшено: " << dropped_packets << "\n";
        std::cout << "Сохранено в файл " << filename << "\n\n\n";
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
        if (packet[i] <= 127)
            output_file << std::setw(2) << packet[i] << " ";
        else
            output_file << ".." << " ";

        if ((i + 1) % 16 == 0)
            output_file << "\n";
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    matched_packets++;
    std::cout << "Найден подходящий пакет " << matched_packets << "\n";
    output_file << "\nПакет " << std::dec << matched_packets << "\n";
    output_file << "Размер пакета: " << header->len << "\n";
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

const char *pick_interface()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    std::vector<std::string> device_names;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Не найдены сетевые интерфейсы: " << errbuf << "\n";
        return nullptr;
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
        return nullptr;
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
    return device_names[choice - 1].c_str();
}

int set_bpf_filter(bpf_u_int32 net)
{

    bpf_program fp;

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
    const char *dev = pick_interface();

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        std::cerr << "Не удалось открыть сетевой интерфейс: " << errbuf << "\n";
        return 1;
    }
    if (pcap_datalink(handle))
    {
    }

    bpf_u_int32 net, mask;
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        net = 0;
        mask = 0;
    }
    else
        std::cout << "Сеть: " << net << " Маска: " << mask << "\n";

    if (set_bpf_filter(net) != 0)
        return 1;

    output_file.open(filename, std::ios::app);
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