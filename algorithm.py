import numpy as np, random, operator, pandas as pd, matplotlib.pyplot as plt, time, random
from ipaddress import IPv4Address, ip_network

df = pd.read_csv("preprocessing/dataset1_downsampled.csv", low_memory=False, header=0)
df = df.sample(n=10000)
print(len(df))
print(df.dtypes)
attacks = df[df['is_attack'] == 1]
normal = df[df['is_attack'] == 0]


class Packet:

    def __init__(self, src=None, sport=None, dst=None, dport=None, proto=None, ttl=None, pkt_len=None, flags=None):
        """
        [32]-[16]-[32]-[16]-[8]-[8]-[16]-[4]
        src-sport-dst-dport-proto-ttl-len-flags
        :param src: from 0.0.0.0 to 255.255.255.255 (00000000-00000000-00000000-00000000)
        :param sport: 0-65536 (00000000 00000000)
        :param dst: from 0.0.0.0 to 255.255.255.255 (00000000-00000000-00000000-00000000)
        :param dport: 0-65536 (00000000 00000000)
        :param proto: 0-255 (00000000)
        :param ttl: 0-255 (00000000)
        :param pkt_len: 0-65536(00000000 00000000)
        :param flags: 0-3 (0000)
        """
        self.src = src if src else "0.0.0.0"
        src_network = []
        for ip in str(self.src).split("."):
            if ip != "0":
                src_network.append(ip)
            else:
                break
        self.src_network = ip_network(
            ".".join(src_network + ["0" for _ in range(4 - len(src_network))]) + "/" + str(8 * len(src_network)))
        self.sport = sport if sport else 0.0
        self.dst = dst if src else "0.0.0.0"
        dst_network = []
        for ip in str(self.dst).split("."):
            if ip != "0":
                dst_network.append(ip)
            else:
                break
        self.dst_network = ip_network(
            ".".join(dst_network + ["0" for _ in range(4 - len(dst_network))]) + "/" + str(8 * len(dst_network)))
        self.dport = dport if dport else 0.0
        self.proto = proto if proto else 0
        self.ttl = ttl if ttl else 0
        self.pkt_len = pkt_len if pkt_len else 0
        self.flags = flags if flags else 0
        self.chromosome = None

    def from_chromosome(self, chromosome):
        self.src = IPv4Address(".".join([str(int(chromosome[i:i + 8], 2)) for i in range(0, len(chromosome[:32]), 8)]))
        src_network = []
        for ip in str(self.src).split("."):
            if ip != "0":
                src_network.append(ip)
            else:
                break
        self.src_network = ip_network(
            ".".join(src_network + ["0" for _ in range(4 - len(src_network))]) + "/" + str(8 * len(src_network)))
        self.sport = float(int(chromosome[32:48], 2))
        self.dst = IPv4Address(
            ".".join([str(int(chromosome[48 + i:i + 56], 2)) for i in range(0, len(chromosome[48:80]), 8)]))
        dst_network = []
        for ip in str(self.dst).split("."):
            if ip != "0":
                dst_network.append(ip)
            else:
                break
        self.dst_network = ip_network(
            ".".join(dst_network + ["0" for _ in range(4 - len(dst_network))]) + "/" + str(8 * len(dst_network)))
        self.dport = float(int(chromosome[80:96], 2))
        self.proto = int(chromosome[96:104], 2)
        self.ttl = int(chromosome[104:112], 2)
        self.pkt_len = int(chromosome[112:128], 2)
        self.flags = int(chromosome[128:], 2)
        self.chromosome = chromosome

    def to_chromosome(self):
        src = []
        for ip in str(self.src).split("."):
            ip_bin = str(bin(int(ip)))[2:]
            src.append("".join(["0" for _ in range(8 - len(ip_bin))]) + ip_bin)
        src_bits = "".join(src)
        dst = []
        for ip in str(self.dst).split("."):
            ip_bin = str(bin(int(ip)))[2:]
            dst.append("".join(["0" for _ in range(8 - len(ip_bin))]) + ip_bin)
        dst_bits = "".join(dst)
        sport_bits = str(bin(self.sport))[2:]
        sport_bits = "".join(["0" for _ in range(16 - len(sport_bits))]) + sport_bits
        dport_bits = str(bin(self.dport))[2:]
        dport_bits = "".join(["0" for _ in range(16 - len(dport_bits))]) + dport_bits
        proto_bits = str(bin(self.proto))[2:]
        proto_bits = "".join(["0" for _ in range(8 - len(proto_bits))]) + proto_bits
        ttl_bits = str(bin(self.ttl))[2:]
        ttl_bits = "".join(["0" for _ in range(8 - len(ttl_bits))]) + ttl_bits
        pkt_len_bits = str(bin(self.pkt_len))[2:]
        pkt_len_bits = "".join(["0" for _ in range(16 - len(pkt_len_bits))]) + pkt_len_bits
        flags_bits = str(bin(self.flags))[2:]
        flags_bits = "".join(["0" for _ in range(4 - len(flags_bits))]) + flags_bits
        chromosome = "".join(
            [src_bits, sport_bits, dst_bits, dport_bits, proto_bits, ttl_bits, pkt_len_bits, flags_bits])
        return chromosome

    def match_packet(self, packet):
        if (IPv4Address(packet['src']) not in self.src_network) or (IPv4Address(packet['dst']) not in self.dst_network) \
                or (self.sport != 0 and packet['sport'] != self.sport) or (
                self.dport != 0 and packet['dport'] != self.dport) \
                or (self.proto != 0 and packet['proto'] != self.proto):
            return 0
        if packet['is_attack'] == 1:
            return 1
        else:
            return -10

    def __repr__(self):
        return f"({self.src}:{self.sport})->({self.dst}:{self.dport}), proto:{self.proto},ttl: {self.ttl}, " \
               f"len:{self.pkt_len}, flags:{self.flags}"


class Fitness:
    def __init__(self):
        self.results = {}

    def calculate_fitness(self, chromosomes: list[Packet]):
        fitness_results = {}
        not_calculated = []
        for i in range(0, len(chromosomes)):
            if repr(chromosomes[i]) not in self.results.keys():
                not_calculated.append(i)
                self.results[repr(chromosomes[i])] = 0
            else:
                fitness_results[i] = self.results[repr(chromosomes[i])]

        for index, row in df.iterrows():
            for i in not_calculated:
                self.results[repr(chromosomes[i])] += chromosomes[i].match_packet(row)

        for i in not_calculated:
            fitness_results[i] = self.results[repr(chromosomes[i])]
        return sorted(fitness_results.items(), key=operator.itemgetter(1), reverse=True)


class CreatePacket:
    def __init__(self):
        self.src_ips = df['src'].to_list()
        self.src_ips_attack = attacks['src'].to_list()

        self.src_ports = df['sport'].to_list()
        self.src_ports_attack = attacks['sport'].to_list()

        self.dst_ips = df['dst'].to_list()
        self.dst_ips_attack = attacks['dst'].to_list()

        self.dst_ports = df['dport'].to_list()
        self.dst_ports_attack = attacks['dport'].to_list()

        self.protocols = df['proto'].to_list()
        self.protocols_attack = attacks['proto'].to_list()

        self.lens = df['len'].to_list()
        self.lens_attack = attacks['len'].to_list()

        self.ttls = df['ttl'].to_list()
        self.ttls_attack = attacks['ttl'].to_list()

        self.flags = list(range(1, 16))

    def generate_packet(self):
        temp_ip_src = random.choice(self.src_ips) if random.random() < .5 else random.choice(self.src_ips_attack)
        src_ip_parts = []
        for ip in temp_ip_src.split("."):
            src_ip_parts.append("0") if random.random() < .3 else src_ip_parts.append(ip)
        src_ip = ".".join(src_ip_parts)
        src_port = random.choice(self.src_ports) if random.random() < .5 else random.choice(self.src_ports_attack)
        src_port = src_port if random.random() < .1 else 0
        temp_ip_dst = random.choice(self.dst_ips) if random.random() < .5 else random.choice(self.dst_ips_attack)
        dst_ip_parts = []
        for ip in temp_ip_dst.split("."):
            dst_ip_parts.append("0") if random.random() < .3 else dst_ip_parts.append(ip)
        dst_ip = ".".join(dst_ip_parts)
        dst_port = random.choice(self.dst_ports) if random.random() < .5 else random.choice(self.dst_ports_attack)
        dst_port = dst_port if random.random() < .95 else 0
        protocol = random.choice(self.protocols) if random.random() < .5 else random.choice(self.protocols_attack)
        protocol = protocol if random.random() < .95 else 0
        pkt_len = random.choice(self.lens) if random.random() < .5 else random.choice(self.lens_attack)
        pkt_len = pkt_len if random.random() < .5 else 0
        ttl = random.choice(self.ttls) if random.random() < .5 else random.choice(self.ttls_attack)
        ttl = ttl if random.random() < .5 else 0

        flag = random.choice(self.flags) if random.random() < .5 else 0
        return Packet(src=src_ip, sport=src_port, dst=dst_ip, dport=dst_port, proto=protocol, ttl=ttl, pkt_len=pkt_len,
                      flags=flag)


def initialPopulation(size):
    createPacket = CreatePacket()
    population = []
    for i in range(0, size):
        population.append(createPacket.generate_packet())
    return population


pkt = Packet()
pkt.from_chromosome("10001011100001100011110100000000"  # src
                    "0000000000000000"  # sport
                    "10101100000100000111001000110010"  # dst
                    "0001011101110000"  # dport
                    "00000110"  # proto
                    "00111111"  # ttl
                    "0000010111011100"  # pkt_len
                    "0010")  # flags

print(repr(pkt))
#
# print(len(attacks[attacks['src'] == '139.134.61.42']))
print(attacks[attacks['src'] == '139.134.61.42'].to_string())
print(normal[normal['src'] == '139.134.61.42'].to_string())


def geneticAlgorithmPlot(popSize, eliteSize, mutationRate, generations):
    population = initialPopulation(popSize)
    for packet in population:
        print(repr(packet))
    progress = []
    fitness = Fitness()
    start_time = time.time()
    current_fitness = fitness.calculate_fitness(population)
    print(current_fitness)
    print(population[current_fitness[0][0]])
    print("Fitness calculation time: {}".format(time.time() - start_time))
    progress.append(current_fitness[0][1])

    for i in range(0, generations):
        start_time = time.time()
        # print("generation {}, fitness: {}, time spent: {}".format(i+1, current_fitness[0][1], time.time() - start_time))
        progress.append(current_fitness[0][1])
        # pop = nextGeneration(pop, eliteSize, mutationRate)
        # progress.append(1 / rankRoutes(pop)[0][1])

    # plt.plot(progress)
    # plt.ylabel('Distance')
    # plt.xlabel('Generation')
    # plt.show()


geneticAlgorithmPlot(popSize=100, eliteSize=20, mutationRate=0.01, generations=500)
# fitness = Fitness()
# start = time.time()
# print(fitness.calculate_fitness(packets))
# print("Time elapsed: ", time.time() - start)
# print(pkt.chromosome)
# print(pkt.to_chromosome())

# if []:
#     print("yes")
# else:
#     print("nop")
#
# print(IPv4Address("192.168.255.1") in ip_network("192.168.255.1/32"))
