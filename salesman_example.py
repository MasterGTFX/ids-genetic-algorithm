{
 "cells": [
  {
   "cell_type": "code",
   "execution_count": 1,
   "metadata": {},
   "outputs": [],
   "source": [
    "import numpy as np, random, operator, pandas as pd, matplotlib.pyplot as plt"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Create necessary classes and functions"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Create class to handle \"cities\""
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 2,
   "metadata": {},
   "outputs": [],
   "source": [
    "class City:\n",
    "    def __init__(self, x, y):\n",
    "        self.x = x\n",
    "        self.y = y\n",
    "    \n",
    "    def distance(self, city):\n",
    "        xDis = abs(self.x - city.x)\n",
    "        yDis = abs(self.y - city.y)\n",
    "        distance = np.sqrt((xDis ** 2) + (yDis ** 2))\n",
    "        return distance\n",
    "    \n",
    "    def __repr__(self):\n",
    "        return \"(\" + str(self.x) + \",\" + str(self.y) + \")\""
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Create a fitness function"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 3,
   "metadata": {},
   "outputs": [],
   "source": [
    "class Fitness:\n",
    "    def __init__(self, route):\n",
    "        self.route = route\n",
    "        self.distance = 0\n",
    "        self.fitness= 0.0\n",
    "    \n",
    "    def routeDistance(self):\n",
    "        if self.distance ==0:\n",
    "            pathDistance = 0\n",
    "            for i in range(0, len(self.route)):\n",
    "                fromCity = self.route[i]\n",
    "                toCity = None\n",
    "                if i + 1 < len(self.route):\n",
    "                    toCity = self.route[i + 1]\n",
    "                else:\n",
    "                    toCity = self.route[0]\n",
    "                pathDistance += fromCity.distance(toCity)\n",
    "            self.distance = pathDistance\n",
    "        return self.distance\n",
    "    \n",
    "    def routeFitness(self):\n",
    "        if self.fitness == 0:\n",
    "            self.fitness = 1 / float(self.routeDistance())\n",
    "        return self.fitness"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Create our initial population"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Route generator"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 4,
   "metadata": {},
   "outputs": [],
   "source": [
    "def createRoute(cityList):\n",
    "    route = random.sample(cityList, len(cityList))\n",
    "    return route"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Create first \"population\" (list of routes)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 5,
   "metadata": {},
   "outputs": [],
   "source": [
    "def initialPopulation(popSize, cityList):\n",
    "    population = []\n",
    "\n",
    "    for i in range(0, popSize):\n",
    "        population.append(createRoute(cityList))\n",
    "    return population"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Create the genetic algorithm"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Rank individuals"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 6,
   "metadata": {},
   "outputs": [],
   "source": [
    "def rankRoutes(population):\n",
    "    fitnessResults = {}\n",
    "    for i in range(0,len(population)):\n",
    "        fitnessResults[i] = Fitness(population[i]).routeFitness()\n",
    "    return sorted(fitnessResults.items(), key = operator.itemgetter(1), reverse = True)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Create a selection function that will be used to make the list of parent routes"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 7,
   "metadata": {},
   "outputs": [],
   "source": [
    "def selection(popRanked, eliteSize):\n",
    "    selectionResults = []\n",
    "    df = pd.DataFrame(np.array(popRanked), columns=[\"Index\",\"Fitness\"])\n",
    "    df['cum_sum'] = df.Fitness.cumsum()\n",
    "    df['cum_perc'] = 100*df.cum_sum/df.Fitness.sum()\n",
    "    \n",
    "    for i in range(0, eliteSize):\n",
    "        selectionResults.append(popRanked[i][0])\n",
    "    for i in range(0, len(popRanked) - eliteSize):\n",
    "        pick = 100*random.random()\n",
    "        for i in range(0, len(popRanked)):\n",
    "            if pick <= df.iat[i,3]:\n",
    "                selectionResults.append(popRanked[i][0])\n",
    "                break\n",
    "    return selectionResults"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Create mating pool"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 8,
   "metadata": {},
   "outputs": [],
   "source": [
    "def matingPool(population, selectionResults):\n",
    "    matingpool = []\n",
    "    for i in range(0, len(selectionResults)):\n",
    "        index = selectionResults[i]\n",
    "        matingpool.append(population[index])\n",
    "    return matingpool"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Create a crossover function for two parents to create one child"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 9,
   "metadata": {},
   "outputs": [],
   "source": [
    "def breed(parent1, parent2):\n",
    "    child = []\n",
    "    childP1 = []\n",
    "    childP2 = []\n",
    "    \n",
    "    geneA = int(random.random() * len(parent1))\n",
    "    geneB = int(random.random() * len(parent1))\n",
    "    \n",
    "    startGene = min(geneA, geneB)\n",
    "    endGene = max(geneA, geneB)\n",
    "\n",
    "    for i in range(startGene, endGene):\n",
    "        childP1.append(parent1[i])\n",
    "        \n",
    "    childP2 = [item for item in parent2 if item not in childP1]\n",
    "\n",
    "    child = childP1 + childP2\n",
    "    return child"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Create function to run crossover over full mating pool"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 10,
   "metadata": {},
   "outputs": [],
   "source": [
    "def breedPopulation(matingpool, eliteSize):\n",
    "    children = []\n",
    "    length = len(matingpool) - eliteSize\n",
    "    pool = random.sample(matingpool, len(matingpool))\n",
    "\n",
    "    for i in range(0,eliteSize):\n",
    "        children.append(matingpool[i])\n",
    "    \n",
    "    for i in range(0, length):\n",
    "        child = breed(pool[i], pool[len(matingpool)-i-1])\n",
    "        children.append(child)\n",
    "    return children"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Create function to mutate a single route"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 11,
   "metadata": {},
   "outputs": [],
   "source": [
    "def mutate(individual, mutationRate):\n",
    "    for swapped in range(len(individual)):\n",
    "        if(random.random() < mutationRate):\n",
    "            swapWith = int(random.random() * len(individual))\n",
    "            \n",
    "            city1 = individual[swapped]\n",
    "            city2 = individual[swapWith]\n",
    "            \n",
    "            individual[swapped] = city2\n",
    "            individual[swapWith] = city1\n",
    "    return individual"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Create function to run mutation over entire population"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 12,
   "metadata": {},
   "outputs": [],
   "source": [
    "def mutatePopulation(population, mutationRate):\n",
    "    mutatedPop = []\n",
    "    \n",
    "    for ind in range(0, len(population)):\n",
    "        mutatedInd = mutate(population[ind], mutationRate)\n",
    "        mutatedPop.append(mutatedInd)\n",
    "    return mutatedPop"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Put all steps together to create the next generation"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 13,
   "metadata": {},
   "outputs": [],
   "source": [
    "def nextGeneration(currentGen, eliteSize, mutationRate):\n",
    "    popRanked = rankRoutes(currentGen)\n",
    "    selectionResults = selection(popRanked, eliteSize)\n",
    "    matingpool = matingPool(currentGen, selectionResults)\n",
    "    children = breedPopulation(matingpool, eliteSize)\n",
    "    nextGeneration = mutatePopulation(children, mutationRate)\n",
    "    return nextGeneration"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Final step: create the genetic algorithm"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 14,
   "metadata": {},
   "outputs": [],
   "source": [
    "def geneticAlgorithm(population, popSize, eliteSize, mutationRate, generations):\n",
    "    pop = initialPopulation(popSize, population)\n",
    "    print(\"Initial distance: \" + str(1 / rankRoutes(pop)[0][1]))\n",
    "    \n",
    "    for i in range(0, generations):\n",
    "        pop = nextGeneration(pop, eliteSize, mutationRate)\n",
    "    \n",
    "    print(\"Final distance: \" + str(1 / rankRoutes(pop)[0][1]))\n",
    "    bestRouteIndex = rankRoutes(pop)[0][0]\n",
    "    bestRoute = pop[bestRouteIndex]\n",
    "    return bestRoute"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Running the genetic algorithm"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Create list of cities"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 15,
   "metadata": {},
   "outputs": [],
   "source": [
    "cityList = []\n",
    "\n",
    "for i in range(0,25):\n",
    "    cityList.append(City(x=int(random.random() * 200), y=int(random.random() * 200)))"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Run the genetic algorithm"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 16,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Initial distance: 2427.0741807710774\n",
      "Final distance: 921.6346703083029\n"
     ]
    },
    {
     "data": {
      "text/plain": [
       "[(160,189),\n",
       " (170,188),\n",
       " (104,118),\n",
       " (63,149),\n",
       " (63,177),\n",
       " (33,185),\n",
       " (27,178),\n",
       " (4,180),\n",
       " (35,118),\n",
       " (36,37),\n",
       " (20,9),\n",
       " (68,26),\n",
       " (78,22),\n",
       " (109,49),\n",
       " (131,9),\n",
       " (176,15),\n",
       " (139,48),\n",
       " (139,65),\n",
       " (160,70),\n",
       " (191,57),\n",
       " (181,90),\n",
       " (195,139),\n",
       " (197,185),\n",
       " (184,178),\n",
       " (176,187)]"
      ]
     },
     "execution_count": 16,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "geneticAlgorithm(population=cityList, popSize=100, eliteSize=20, mutationRate=0.01, generations=500)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Plot the progress"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Note, this will win run a separate GA"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 17,
   "metadata": {},
   "outputs": [],
   "source": [
    "def geneticAlgorithmPlot(population, popSize, eliteSize, mutationRate, generations):\n",
    "    pop = initialPopulation(popSize, population)\n",
    "    progress = []\n",
    "    progress.append(1 / rankRoutes(pop)[0][1])\n",
    "    \n",
    "    for i in range(0, generations):\n",
    "        pop = nextGeneration(pop, eliteSize, mutationRate)\n",
    "        progress.append(1 / rankRoutes(pop)[0][1])\n",
    "    \n",
    "    plt.plot(progress)\n",
    "    plt.ylabel('Distance')\n",
    "    plt.xlabel('Generation')\n",
    "    plt.show()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Run the function with our assumptions to see how distance has improved in each generation"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 18,
   "metadata": {},
   "outputs": [
    {
     "data": {
      "image/png": "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\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0x1cc1ebee4a8>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "geneticAlgorithmPlot(population=cityList, popSize=100, eliteSize=20, mutationRate=0.01, generations=500)"
   ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 3
   },
   "file_extension": ".py",
   "mimetype": "text/x-python",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython3",
   "version": "3.6.4"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 2
}