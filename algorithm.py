import numpy as np, operator, pandas as pd, matplotlib.pyplot as plt, time, random
from ipaddress import IPv4Address, ip_network

#df = pd.read_csv("preprocessing/dataset1_downsampled.csv", low_memory=False, header=0)
df = pd.read_csv("preprocessing/dataset1_fix2.csv", low_memory=False, header=0)
df['sport'] = df['sport'].apply(lambda x: 0 if pd.isnull(x) else float(x))
df['dport'] = df['dport'].apply(lambda x: 0 if pd.isnull(x) else float(x))
# df = df.sample(n=10000)
# print(len(df))
# print(df.dtypes)
attacks = df[df['is_attack'] == 1]
normal = df[df['is_attack'] == 0]


# print(len(attacks), len(normal))


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
        :param flags: 0-3 (000)
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
        sport_bits = str(bin(int(self.sport)))[2:]
        sport_bits = "".join(["0" for _ in range(16 - len(sport_bits))]) + sport_bits
        dport_bits = str(bin(int(self.dport)))[2:]
        dport_bits = "".join(["0" for _ in range(16 - len(dport_bits))]) + dport_bits
        proto_bits = str(bin(self.proto))[2:]
        proto_bits = "".join(["0" for _ in range(8 - len(proto_bits))]) + proto_bits
        ttl_bits = str(bin(self.ttl))[2:]
        ttl_bits = "".join(["0" for _ in range(8 - len(ttl_bits))]) + ttl_bits
        pkt_len_bits = str(bin(self.pkt_len))[2:]
        pkt_len_bits = "".join(["0" for _ in range(16 - len(pkt_len_bits))]) + pkt_len_bits
        flags_bits = str(bin(self.flags))[2:]
        flags_bits = "".join(["0" for _ in range(3 - len(flags_bits))]) + flags_bits
        chromosome = "".join(
            [src_bits, sport_bits, dst_bits, dport_bits, proto_bits, ttl_bits, pkt_len_bits, flags_bits])
        return chromosome

    def fitness_match(self, packet):
        if (IPv4Address(packet['src']) not in self.src_network) or (IPv4Address(packet['dst']) not in self.dst_network) \
                or (self.sport != 0 and packet['sport'] != self.sport) or (
                self.dport != 0 and packet['dport'] != self.dport) \
                or (self.proto != 0 and packet['proto'] != self.proto):
            return 0
        if packet['is_attack'] == 1:
            return 1
        else:
            return -10

    def fitness_analyze(self, packets_count):
        attack_scale = packets_count['normal_count']/packets_count['attacks_count']
        src_ip_attacks = 0
        for src_ip in packets_count['src_attack']:
            if src_ip in self.src_network:
                src_ip_attacks += packets_count['src_attack'][src_ip]
        src_ip_attacks /= packets_count['attacks_count']
        #src_ip_attacks *= attack_scale
        src_ip_normal = 0
        for src_ip in packets_count['src_normal']:
            if src_ip in self.src_network:
                src_ip_normal += packets_count['src_normal'][src_ip]
        src_ip_normal /= packets_count['normal_count']
        src_ip_score = src_ip_attacks - src_ip_normal

        dst_ip_attacks = 0
        for dst_ip in packets_count['dst_attack']:
            if dst_ip in self.dst_network:
                dst_ip_attacks += packets_count['dst_attack'][dst_ip]
        dst_ip_attacks /= packets_count['attacks_count']
        #dst_ip_attacks *= attack_scale
        dst_ip_normal = 0
        for dst_ip in packets_count['dst_normal']:
            if dst_ip in self.dst_network:
                dst_ip_normal += packets_count['dst_normal'][dst_ip]
        dst_ip_normal /= packets_count['normal_count']
        dst_ip_score = dst_ip_attacks - dst_ip_normal

        try:
            dst_port_attacks = packets_count['dport_attack'][self.dport] + packets_count['dport_attack'][
                0] if self.dport != 0 else packets_count['attacks_count']
        except KeyError:
            dst_port_attacks = packets_count['dport_attack'][0]
        dst_port_attacks /= packets_count['attacks_count']
        #dst_port_attacks *= attack_scale
        try:
            dst_port_normal = packets_count['dport_normal'][self.dport] + packets_count['dport_normal'][
                0] if self.dport != 0 else packets_count['normal_count']
        except KeyError:
            dst_port_normal = packets_count['dport_normal'][0]
        dst_port_normal /= packets_count['normal_count']
        dst_port_score = dst_port_attacks - dst_port_normal

        try:
            src_port_attacks = packets_count['sport_attack'][self.dport] + packets_count['sport_attack'][
                0] if self.dport != 0 else packets_count['attacks_count']
        except KeyError:
            src_port_attacks = packets_count['sport_attack'][0]
        src_port_attacks /= packets_count['attacks_count']
        #src_port_attacks *= attack_scale
        try:
            src_port_normal = packets_count['sport_normal'][self.dport] + packets_count['sport_normal'][
                0] if self.dport != 0 else packets_count['normal_count']
        except KeyError:
            src_port_normal = packets_count['sport_normal'][0]
        src_port_normal /= packets_count['normal_count']
        src_port_score = src_port_attacks - src_port_normal

        try:
            pkt_len_attacks = packets_count['len_attack'][self.pkt_len] if self.pkt_len != 0 else packets_count[
                'attacks_count']
            pkt_len_attacks /= packets_count['attacks_count']
            #pkt_len_attacks *= attack_scale
        except KeyError:
            pkt_len_attacks = 0
        try:
            pkt_len_normal = packets_count['len_normal'][self.pkt_len] if self.pkt_len != 0 else packets_count[
                'normal_count']
            pkt_len_normal /= packets_count['normal_count']
        except KeyError:
            pkt_len_normal = 0
        pkt_len_score = pkt_len_attacks - pkt_len_normal

        try:
            ttl_attacks = packets_count['ttl_attack'][self.ttl] if self.ttl != 0 else packets_count['attacks_count']
            ttl_attacks /= packets_count['attacks_count']
            #ttl_attacks *= attack_scale
        except KeyError:
            ttl_attacks = 0
        try:
            ttl_normal = packets_count['ttl_normal'][self.ttl] if self.ttl != 0 else packets_count['normal_count']
            ttl_normal /= packets_count['normal_count']
        except KeyError:
            ttl_normal = 0
        ttl_score = ttl_attacks - ttl_normal

        try:
            proto_attacks = packets_count['proto_attack'][self.proto] if self.proto != 0 else packets_count[
                'attacks_count']
            proto_attacks /= packets_count['attacks_count']
            #proto_attacks *= attack_scale
        except KeyError:
            proto_attacks = 0
        try:
            proto_normal = packets_count['proto_normal'][self.proto] if self.proto != 0 else packets_count[
                'normal_count']
            proto_normal /= packets_count['normal_count']
        except KeyError:
            proto_normal = 0
        proto_score = proto_attacks - proto_normal

        try:
            if self.flags == 2:
                flags_attacks = packets_count['flags_attack']['DF']
            elif self.flags == 4:
                flags_attacks = packets_count['flags_attack']['MF']
            else:
                flags_attacks = 0
            flags_attacks /= packets_count['attacks_count']
            #flags_attacks *= attack_scale
        except KeyError:
            flags_attacks = 0
        try:
            if self.flags == 2:
                flags_normal = packets_count['flags_normal']['DF']
            elif self.flags == 4:
                flags_normal = packets_count['flags_normal']['MF']
            else:
                flags_normal = 0
            flags_normal /= packets_count['normal_count']
        except KeyError:
            flags_normal = 0
        flags_score = flags_attacks - flags_normal
        # src_ip_score
        # 0.21, -0.34
        # src_port_score
        # 0.11, -0.14
        # dst_ip_score
        # 0.25, -0.04
        # dst_port_score
        # 0.30, -0.20
        # pkt_len_score
        # 0.11, -0.28
        # proto_score
        # 0.14, -0.13
        # ttl_score
        # 0.33, -0.28
        # flags_score
        # 0.17, 0 *, -0.000002
        src_ip_score + src_port_score + dst_ip_score + dst_port_score + pkt_len_score + proto_score + ttl_score + flags_score
        #return 5 * 3 * src_ip_score + 8 * src_port_score + 4 * 4 * dst_ip_score + 4 * 4 * dst_port_score + 2 * 4 * pkt_len_score + 3 * 9 * proto_score + 2 * 3 * ttl_score + 4 * flags_score
        return 6 * src_ip_score + src_port_score + 4 * dst_ip_score + 5 *  dst_port_score + 2 * pkt_len_score + 2 * proto_score + 2 * ttl_score + flags_score
        #return 5 * src_ip_score + src_port_score + 4 * dst_ip_score + 4 * dst_port_score + 2 * pkt_len_score + 3 * proto_score + 2 * ttl_score + flags_score

    def __repr__(self):
        return f"({self.src_network}:{self.sport})->({self.dst_network}:{self.dport}), proto:{self.proto},ttl: {self.ttl}, " \
               f"len:{self.pkt_len}, flags:{self.flags}"


class Fitness:
    def __init__(self):
        self.results = {}
        self.packets_count = {}

    def calculate_fitness_match(self, chromosomes: list[Packet]):
        fitness_results = {}
        not_calculated = []
        for i in range(0, len(chromosomes)):
            if repr(chromosomes[i]) not in self.results.keys():
                not_calculated.append(i)
                self.results[repr(chromosomes[i])] = 0
            else:
                fitness_results[i] = self.results[repr(chromosomes[i])]
        # fitness with 'match' method
        for index, row in df.iterrows():
            for i in not_calculated:
                self.results[repr(chromosomes[i])] += chromosomes[i].fitness_match(row)

        for i in not_calculated:
            fitness_results[i] = self.results[repr(chromosomes[i])]
        return sorted(fitness_results.items(), key=operator.itemgetter(1), reverse=True)

    def calculate_fitness_similiar(self, chromosomes: list[Packet]):
        if not self.packets_count:
            self.packets_count['attacks_count'] = len(attacks)
            self.packets_count['normal_count'] = len(normal)

            self.packets_count['src_normal'] = dict(normal['src'].value_counts(dropna=False))
            self.packets_count['src_normal'] = {IPv4Address(k): int(v) for k, v in
                                                self.packets_count['src_normal'].items()}
            self.packets_count['src_attack'] = dict(attacks['src'].value_counts(dropna=False))
            self.packets_count['src_attack'] = {IPv4Address(k): int(v) for k, v in
                                                self.packets_count['src_attack'].items()}

            self.packets_count['sport_normal'] = dict(normal['sport'].value_counts(dropna=False))
            self.packets_count['sport_normal'] = {int(k): int(v) for k, v in
                                                  self.packets_count['sport_normal'].items()}
            self.packets_count['sport_attack'] = dict(attacks['sport'].value_counts(dropna=False))
            self.packets_count['sport_attack'] = {int(k): int(v) for k, v in
                                                  self.packets_count['sport_attack'].items()}

            self.packets_count['dst_normal'] = dict(normal['dst'].value_counts(dropna=False))
            self.packets_count['dst_normal'] = {IPv4Address(k): int(v) for k, v in
                                                self.packets_count['dst_normal'].items()}
            self.packets_count['dst_attack'] = dict(attacks['dst'].value_counts(dropna=False))
            self.packets_count['dst_attack'] = {IPv4Address(k): int(v) for k, v in
                                                self.packets_count['dst_attack'].items()}

            self.packets_count['dport_normal'] = dict(normal['dport'].value_counts(dropna=False))
            self.packets_count['dport_normal'] = {int(k): int(v) for k, v in
                                                  self.packets_count['dport_normal'].items()}
            self.packets_count['dport_attack'] = dict(attacks['dport'].value_counts(dropna=False))
            self.packets_count['dport_attack'] = {int(k): int(v) for k, v in
                                                  self.packets_count['dport_attack'].items()}

            self.packets_count['ttl_normal'] = dict(normal['ttl'].value_counts(dropna=False))
            self.packets_count['ttl_normal'] = {int(k): int(v) for k, v in
                                                self.packets_count['ttl_normal'].items()}
            self.packets_count['ttl_attack'] = dict(attacks['ttl'].value_counts(dropna=False))
            self.packets_count['ttl_attack'] = {int(k): int(v) for k, v in
                                                self.packets_count['ttl_attack'].items()}

            self.packets_count['proto_normal'] = dict(normal['proto'].value_counts(dropna=False))
            self.packets_count['proto_normal'] = {int(k): int(v) for k, v in
                                                  self.packets_count['proto_normal'].items()}
            self.packets_count['proto_attack'] = dict(attacks['proto'].value_counts(dropna=False))
            self.packets_count['proto_attack'] = {int(k): int(v) for k, v in
                                                  self.packets_count['proto_attack'].items()}

            self.packets_count['flags_normal'] = dict(normal['flags'].value_counts())
            self.packets_count['flags_attack'] = dict(attacks['flags'].value_counts())

            self.packets_count['len_normal'] = dict(normal['len'].value_counts(dropna=False))
            self.packets_count['len_normal'] = {int(k): int(v) for k, v in
                                                self.packets_count['len_normal'].items()}
            self.packets_count['len_attack'] = dict(attacks['len'].value_counts(dropna=False))
            self.packets_count['len_attack'] = {int(k): int(v) for k, v in
                                                self.packets_count['len_attack'].items()}

        fitness_results = {}
        not_calculated = []
        for i in range(0, len(chromosomes)):
            if repr(chromosomes[i]) not in self.results.keys():
                not_calculated.append(i)
                self.results[repr(chromosomes[i])] = 0
            else:
                fitness_results[i] = self.results[repr(chromosomes[i])]
        # fitness with 'analyze' method
        for i in not_calculated:
            self.results[repr(chromosomes[i])] += chromosomes[i].fitness_analyze(self.packets_count)

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

        self.src_ips = list(set(self.src_ips))
        self.src_ips_attack = list(set(self.src_ips_attack))
        self.src_ports = list(set(self.src_ports))
        self.src_ports_attack = list(set(self.src_ports_attack))
        self.dst_ips = list(set(self.dst_ips))
        self.dst_ips_attack = list(set(self.dst_ips_attack))
        self.dst_ports = list(set(self.dst_ports))
        self.dst_ports_attack = list(set(self.dst_ports_attack))
        self.protocols = list(set(self.protocols))
        self.protocols_attack = list(set(self.protocols_attack))
        self.lens = list(set(self.lens))
        self.lens_attack = list(set(self.lens_attack))
        self.ttls = list(set(self.ttls))
        self.ttls_attack = list(set(self.ttls_attack))
        self.flags = list(range(1, 8))

    def generate_packet(self):
        temp_ip_src = random.choice(self.src_ips) if random.random() < .5 else random.choice(self.src_ips_attack)
        src_ip_parts = []
        for ip in temp_ip_src.split("."):
            src_ip_parts.append("0") if random.random() < .1 else src_ip_parts.append(ip)
        src_ip = ".".join(src_ip_parts)
        src_port = random.choice(self.src_ports) if random.random() < .5 else random.choice(self.src_ports_attack)
        src_port = src_port if random.random() < .1 else 0
        temp_ip_dst = random.choice(self.dst_ips) if random.random() < .5 else random.choice(self.dst_ips_attack)
        dst_ip_parts = []
        for ip in temp_ip_dst.split("."):
            dst_ip_parts.append("0") if random.random() < .1 else dst_ip_parts.append(ip)
        dst_ip = ".".join(dst_ip_parts)
        dst_port = random.choice(self.dst_ports) if random.random() < .5 else random.choice(self.dst_ports_attack)
        dst_port = dst_port if random.random() < .95 else 0
        protocol = random.choice(self.protocols) if random.random() < .5 else random.choice(self.protocols_attack)
        protocol = protocol if random.random() < .95 else 0
        pkt_len = random.choice(self.lens) if random.random() < .5 else random.choice(self.lens_attack)
        pkt_len = pkt_len if random.random() < .5 else 0
        ttl = random.choice(self.ttls) if random.random() < .5 else random.choice(self.ttls_attack)
        ttl = ttl if random.random() < .3 else 0
        flag = random.choice(self.flags) if random.random() < .05 else 0
        return Packet(src=src_ip, sport=src_port, dst=dst_ip, dport=dst_port, proto=protocol, ttl=ttl, pkt_len=pkt_len,
                      flags=flag)


def initialPopulation(size):
    createPacket = CreatePacket()
    population = []
    for i in range(0, size):
        population.append(createPacket.generate_packet())
    return population


#
# print(len(attacks[attacks['src'] == '139.134.61.42']))
# print(attacks[attacks['src'] == '139.134.61.42'].to_string())
# print(normal[normal['src'] == '139.134.61.42'].to_string())

def selection(popRanked, eliteSize):
    selectionResults = []
    df = pd.DataFrame(np.array(popRanked), columns=["Index", "Fitness"])
    min_fitness = min(df['Fitness'].to_list())
    df['Fitness'] += abs(min_fitness)
   # df['Fitness'] = df['Fitness'] * df['Fitness']
    df['cum_sum'] = df.Fitness.cumsum()
    df['cum_perc'] = 100 * df.cum_sum / df.Fitness.sum()

    for i in range(0, eliteSize):
        selectionResults.append(popRanked[i][0])
    for i in range(0, len(popRanked) - eliteSize):
        pick = 100 * random.random()
        for i in range(0, len(popRanked)):
            if pick <= df.iat[i, 3]:
                selectionResults.append(popRanked[i][0])
                break
    return selectionResults


def mutate(individual, mutationRate):
    individual_chromosome = list(individual.to_chromosome())
    for ind in range(len(individual_chromosome)):
        if (random.random() < mutationRate):
            individual_chromosome[ind] = "1" if individual_chromosome[ind] == "0" else "0"
    mutatedInvidual = Packet()
    mutatedInvidual.from_chromosome("".join(individual_chromosome))
    return individual


def mutatePopulation(population, mutationRate):
    mutatedPop = []

    for ind in range(0, len(population)):
        mutatedInd = mutate(population[ind], mutationRate)
        mutatedPop.append(mutatedInd)
    return mutatedPop


def matingPool(population, selectionResults):
    matingpool = []
    for i in range(0, len(selectionResults)):
        index = selectionResults[i]
        matingpool.append(population[index])
    return matingpool


def breed(parent1, parent2):
    P1 = list(parent1.to_chromosome())
    P2 = list(parent2.to_chromosome())
   # print("".join(P1))
   # print("".join(P2))
    geneA = int(random.random() * len(P1))
    geneB = int(random.random() * len(P1))

    startGene = min(geneA, geneB)
    endGene = max(geneA, geneB)

    childChromosome = P1
    childChromosome[startGene:endGene] = P2[startGene:endGene]
    #childChromosome[geneA:] = P2[geneA:]
    #print("".join(childChromosome))
   # print()
    child = Packet()
    child.from_chromosome("".join(childChromosome))
    return child


def breedPopulation(matingpool, eliteSize):
    children = []
    length = len(matingpool) - eliteSize
    pool = random.sample(matingpool, len(matingpool))

    for i in range(0, eliteSize):
        children.append(matingpool[i])

    for i in range(0, length):
        child = breed(pool[i], pool[len(matingpool) - i - 1])
        children.append(child)
    return children


def next_generation(currentGen, eliteSize, mutationRate, fitness):
    popRanked = fitness.calculate_fitness_similiar(currentGen)
    selectionResults = selection(popRanked, eliteSize)
    matingpool = matingPool(currentGen, selectionResults)
    children = breedPopulation(matingpool, eliteSize)
    nextGeneration = mutatePopulation(children, mutationRate)
    print(nextGeneration[:100])
    return nextGeneration


def geneticAlgorithmPlot(popSize, eliteSize, mutationRate, generations):
    population = initialPopulation(popSize)
    # for packet in population:
    #     print(repr(packet))
    progress = []
    fitness = Fitness()
    start_time = time.time()
    #current_fitness = fitness.calculate_fitness_match(population)
    current_fitness = fitness.calculate_fitness_similiar(population)
    progress.append(current_fitness[0][1])
    # print(current_fitness)
    # print(current_fitness[0][1], current_fitness[-1][1])

    print("Fitness precalculation time: {}".format(time.time() - start_time))

    for i in range(0, generations):
        start_time = time.time()
        population = next_generation(population, eliteSize, mutationRate, fitness)
        # pop = nextGeneration(pop, eliteSize, mutationRate)
        #current_fitness = fitness.calculate_fitness_match(population)
        current_fitness = fitness.calculate_fitness_similiar(population)
        progress.append(current_fitness[0][1])
        #print(current_fitness)
        print(
            "generation {}, fitness: {}, time spent: {}".format(i + 1, current_fitness[0][1], time.time() - start_time))

    plt.plot(progress)
    plt.ylabel('Fitness')
    plt.xlabel('Generation')
    plt.show()


geneticAlgorithmPlot(popSize=1000, eliteSize=10, mutationRate=0.2, generations=30)

# pkt = Packet()
# pkt.from_chromosome("10001011100001100011110100000000"  # src
#                     "0000000000000000"  # sport
#                     "10101100000100000111001000110010"  # dst
#                     "0001011101110000"  # dport
#                     "00000110"  # proto
#                     "00111111"  # ttl
#                     "0000010111011100"  # pkt_len
#                     "001")  # flags
# print(pkt.to_chromosome())
# print(repr(pkt))
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
