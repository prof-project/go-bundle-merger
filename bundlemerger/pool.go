package bundlemerger

import (
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
	"log"
	"sort"
	"strconv"
	"sync"
	"time"
)

type TxBundle struct {
	Txs               []*types.Transaction // Array of transactions
	BlockNumber       string               // Hex-encoded block number
	MinTimestamp      int64                // Optional minimum timestamp
	MaxTimestamp      int64                // Optional maximum timestamp
	RevertingTxHashes []string             // Optional list of tx hashes allowed to revert
	ReplacementUuid   string               // Optional replacement UUID
	Builders          []string             // Optional list of builder names
	MarkedForDeletion bool                 // Flag for deletion from the TxBundlePool
}

type TxBundlePool struct {
	bundles    []*TxBundle                 // Store bundles of individual transactions
	bundleMap  map[string]*TxBundle        // Use a map to track bundles by UUID
	mu         sync.RWMutex                // A mutex for concurrent access
	customSort func(b1, b2 *TxBundle) bool // The policy for bundle ordering
}

func (p *TxBundlePool) addBundle(bundle *TxBundle, replace bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if a bundle with the same replacementUuid already exists
	existingBundle, exists := p.bundleMap[bundle.ReplacementUuid]
	if exists {
		// Check if the existing bundle is marked for deletion
		if existingBundle.MarkedForDeletion {
			log.Printf("Existing bundle with UUID %s is marked for deletion, replacing with new bundle.", bundle.ReplacementUuid)

			// Remove the existing bundle from the list
			for i, b := range p.bundles {
				if b.ReplacementUuid == existingBundle.ReplacementUuid {
					p.bundles = append(p.bundles[:i], p.bundles[i+1:]...)
					break
				}
			}
		} else {
			if !replace {
				// If replace is false and the bundle exists (and isn't marked for deletion), return an error
				return fmt.Errorf("bundle with UUID %s already exists", bundle.ReplacementUuid)
			}

			// If replace is true and the existing bundle isn't marked for deletion, replace the existing bundle
			log.Printf("Replacing existing bundle with UUID: %s", bundle.ReplacementUuid)

			// Remove the existing bundle from the list
			for i, b := range p.bundles {
				if b.ReplacementUuid == existingBundle.ReplacementUuid {
					p.bundles = append(p.bundles[:i], p.bundles[i+1:]...)
					break
				}
			}
		}
	}

	// Add the new bundle to the map and the list
	p.bundleMap[bundle.ReplacementUuid] = bundle
	p.bundles = append(p.bundles, bundle)

	// Sort the pool based on the custom sorting policy
	p.sortPool()

	return nil
}

func (p *TxBundlePool) sortPool() {
	sort.Slice(p.bundles, func(i, j int) bool {
		return p.customSort(p.bundles[i], p.bundles[j])
	})
}

// // sorting policies
// sort by block number
func sortByBlockNumber(b1, b2 *TxBundle) bool {
	bn1, _ := strconv.ParseInt(b1.BlockNumber, 0, 64)
	bn2, _ := strconv.ParseInt(b2.BlockNumber, 0, 64)

	return bn1 < bn2 // Sort in ascending order
}

// sort by min timestamp, in ascending order
func sortByMinTimestamp(b1, b2 *TxBundle) bool {
	return b1.MinTimestamp < b2.MinTimestamp
}

// sort by max timestamp, in descending order
func sortByMaxTimestamp(b1, b2 *TxBundle) bool {
	return b1.MaxTimestamp > b2.MaxTimestamp
}

// ToDo: sort by gas price
/*func sortByGasPrice(b1, b2 *TxBundle) bool {
	maxGasPriceB1 := extractMaxGasPrice(b1.Txs)
	maxGasPriceB2 := extractMaxGasPrice(b2.Txs)

	return maxGasPriceB1 > maxGasPriceB2 // Sort in descending order
}

// Helper function to extract max gas price (simplified)
func extractMaxGasPrice(txs []*types.Transaction) big.Int {
	maxGasPrice := big.NewInt(0)
	for _, tx := range txs {
		if tx.GasPrice() > maxGasPrice {
			maxGasPrice = tx.GasPrice
		}
	}
	return maxGasPrice
}*/

// ToDo: sort by builder priority
func sortByBuilderPriority(b1, b2 *TxBundle) bool {
	priorityB1 := getBuilderPriority(b1.Builders)
	priorityB2 := getBuilderPriority(b2.Builders)

	return priorityB1 > priorityB2 // Higher priority number is more important
}

// Helper function to assign priority to builders
func getBuilderPriority(builders []string) int {
	priority := 0 // Default to low priority
	for _, builder := range builders {
		switch builder {
		case "flashbots":
			priority = max(priority, 10)
		case "Titan":
			priority = max(priority, 20)
		default:
			// do nothing
		}
	}
	return priority
}

func (p *TxBundlePool) markBundleForDeletion(bundle *TxBundle) {
	p.mu.Lock()
	defer p.mu.Unlock()

	bundle.MarkedForDeletion = true
}

func (p *TxBundlePool) markBundlesForDeletion(bundles []*TxBundle) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, bundle := range bundles {
		bundle.MarkedForDeletion = true
	}
}

func (p *TxBundlePool) cancelBundleByUuid(uuid string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if the bundle exists in the map
	bundle, exists := p.bundleMap[uuid]
	if !exists {
		return fmt.Errorf("bundle with UUID %s not found", uuid)
	}

	// Mark the bundle for deletion
	bundle.MarkedForDeletion = true
	log.Printf("Bundle with UUID %s marked for deletion\n", uuid)

	return nil
}

func (p *TxBundlePool) cleanupMarkedBundles() {
	p.mu.Lock()
	defer p.mu.Unlock()

	newBundles := []*TxBundle{}
	for _, bundle := range p.bundles {
		if !bundle.MarkedForDeletion {
			newBundles = append(newBundles, bundle)
		} else {
			delete(p.bundleMap, bundle.ReplacementUuid) // Remove from map
		}
	}
	p.bundles = newBundles
}

func (p *TxBundlePool) getBundlesForProcessing(limit int) []*TxBundle {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var selectedBundles []*TxBundle
	for _, bundle := range p.bundles {
		if !bundle.MarkedForDeletion {
			selectedBundles = append(selectedBundles, bundle)
			if len(selectedBundles) >= limit {
				break
			}
		}
	}
	return selectedBundles
}

func (p *TxBundlePool) startCleanupJob(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				startTime := time.Now() // Timestamp before cleanup
				p.cleanupMarkedBundles()
				endTime := time.Now() // Timestamp after cleanup

				// Log the cleanup duration for better debugging and visibility
				log.Printf("Cleanup job took %v", endTime.Sub(startTime))
			}
		}
	}()
}
