package focalpoint

import (
	"fmt"
	"math"
	"strings"
)

type node struct {
	pubkey   string
	ranking  float64
	outbound float64
}

// Graph holds node and edge data.
type Graph struct {
	index map[string]uint32
	nodes map[uint32]*node
	edges map[uint32](map[uint32]float64)
}

// NewGraph initializes and returns a new graph.
func NewGraph() *Graph {
	return &Graph{
		edges: make(map[uint32](map[uint32]float64)),
		nodes: make(map[uint32]*node),
		index: make(map[string]uint32),
	}
}

// Link creates a weighted edge between a source-target node pair.
// If the edge already exists, the weight is incremented.
func (graph *Graph) Link(src, trgt string, weight float64) float64 {
	source := padTo44Characters(src)
	target := padTo44Characters(trgt)
	if _, ok := graph.index[source]; !ok {
		index := uint32(len(graph.index))
		graph.index[source] = index
		graph.nodes[index] = &node{
			ranking:  0,
			outbound: 0,
			pubkey:   source,
		}
	}

	if _, ok := graph.index[target]; !ok {
		index := uint32(len(graph.index))
		graph.index[target] = index
		graph.nodes[index] = &node{
			ranking:  0,
			outbound: 0,
			pubkey:   target,
		}
	}

	sIndex := graph.index[source]
	tIndex := graph.index[target]

	if _, ok := graph.edges[sIndex]; !ok {
		graph.edges[sIndex] = map[uint32]float64{}
	}

	graph.nodes[sIndex].outbound += weight
	graph.edges[sIndex][tIndex] += weight

	return weight
}

func (g *Graph) ToDOT(pubKey string, indices []string, synonyms map[string]string) string {

	pkIndex := g.index[pubKey] //defaults to zero- the viewpoint

	var builder strings.Builder
	builder.WriteString("digraph G {\n")

	includedNodes := []uint32{}

	for from, edge := range g.edges {
		for to, weight := range edge {
			if (from == pkIndex || to == pkIndex) && weight > 0 {

				builder.WriteString(fmt.Sprintf("  \"%d\" -> \"%d\" [weight=\"%f\"];\n", from, to, weight))

				if !containsInt(includedNodes, from) {
					includedNodes = append(includedNodes, from)
				}

				if !containsInt(includedNodes, to) {
					includedNodes = append(includedNodes, to)
				}
			}
		}
	}

	// Add nodes with ranks
	for _, id := range includedNodes {
		node := g.nodes[id]
		label := fmt.Sprintf("%.*s", 15, strings.TrimRight(node.pubkey, "/0="))
		locale := ""
		lIndex := -1

		if node.pubkey == padTo44Characters("0") {
			lIndex = 0
		}

		if synonym, ok := synonyms[node.pubkey]; ok {
			label = synonym
		}

		if ok, locl, _ := localeFromPubKey(node.pubkey, indices); ok {
			locale = locl
			lIndex = localeIndex(locl, indices)

			if synonym, ok := synonyms[padTo44Characters(locale)]; ok {
				label = synonym
			}

			if okk, _, _, _ := inflateNodes(node.pubkey); okk {
				lIndex = -1 //reset to -1
				if syn, ok := synonyms[node.pubkey]; ok {
					label = syn
				}
			}
		}

		builder.WriteString(fmt.Sprintf(
			"  \"%d\" [label=\"%s\", pubkey=\"%s\", locale=\"%s\", localeIndex=\"%d\", ranking=\"%f\"];\n",
			id, label, node.pubkey, locale, lIndex, node.ranking,
		))
	}

	builder.WriteString("}\n")
	return builder.String()
}

func containsInt(slice []uint32, value uint32) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// Checks for relationship to prevent cycles.
func (g *Graph) IsParentDescendant(parent, descendant string) bool {
	parentIndex, pok := g.index[parent]
	descendantIndex, dok := g.index[descendant]

	if !pok || !dok {
		return false
	}

	if parentIndex == 0 || descendantIndex == 0 {
		return false
	}

	visited := make(map[uint32]bool)
	return g.dfs(parentIndex, descendantIndex, visited)
}

func (g *Graph) dfs(current, target uint32, visited map[uint32]bool) bool {
	if current == target {
		return true
	}

	visited[current] = true

	for edge := range g.edges[current] {
		if edge == 0 {// Skip the root node
			continue
		}

		if !visited[edge] {
			if g.dfs(edge, target, visited) {
				return true
			}
		}
	}

	return false
}

// https://github.com/alixaxel/pagerank/blob/master/pagerank.go
// This computes the Rank of every node in the directed graph.
// α (alpha) is the damping factor, usually set to 0.85.
// ε (epsilon) is the convergence criteria, usually set to a tiny value.
//
// This method will run as many iterations as needed, until the graph converges.
func (graph *Graph) Rank(alpha, epsilon float64) {

	normalizedWeights := make(map[uint32](map[uint32]float64))

	Δ := float64(1.0)
	inverse := 1 / float64(len(graph.nodes))

	// Normalize all the edge weights so that their sum amounts to 1.
	for source := range graph.edges {
		if graph.nodes[source].outbound > 0 {
			normalizedWeights[source] = make(map[uint32]float64)
			for target := range graph.edges[source] {
				normalizedWeights[source][target] = graph.edges[source][target] / graph.nodes[source].outbound
			}
		}
	}

	for key := range graph.nodes {
		graph.nodes[key].ranking = inverse
	}

	for Δ > epsilon {
		leak := float64(0)
		nodes := map[uint32]float64{}

		for key, value := range graph.nodes {
			nodes[key] = value.ranking

			if value.outbound == 0 {
				leak += value.ranking
			}

			graph.nodes[key].ranking = 0
		}

		leak *= alpha

		for source := range graph.nodes {
			for target, weight := range normalizedWeights[source] {
				graph.nodes[target].ranking += alpha * nodes[source] * weight
			}

			graph.nodes[source].ranking += (1-alpha)*inverse + leak*inverse
		}

		Δ = 0

		for key, value := range graph.nodes {
			Δ += math.Abs(value.ranking - nodes[key])
		}
	}
}

// Reset clears all the current graph data.
func (graph *Graph) Reset() {
	graph.edges = make(map[uint32](map[uint32]float64))
	graph.nodes = make(map[uint32]*node)
	graph.index = make(map[string]uint32)
}
