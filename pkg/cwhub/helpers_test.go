package cwhub

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Download index, install collection. Add scenario to collection (hub-side), update index, upgrade collection
// We expect the new scenario to be installed
func TestUpgradeConfigNewScenarioInCollection(t *testing.T) {
	cfg := envSetup(t)
	defer envTearDown(cfg)

	// fresh install of collection
	getHubIdxOrFail(t)

	require.False(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Downloaded)
	require.False(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Installed)

	require.NoError(t, InstallItem(cfg, "asians-cloud/test_collection", COLLECTIONS, false, false))

	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Downloaded)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Installed)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].UpToDate)
	require.False(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Tainted)

	// This is the scenario that gets added in next version of collection
	require.False(t, hubIdx[SCENARIOS]["asians-cloud/barfoo_scenario"].Downloaded)
	require.False(t, hubIdx[SCENARIOS]["asians-cloud/barfoo_scenario"].Installed)

	assertCollectionDepsInstalled(t, "asians-cloud/test_collection")

	// collection receives an update. It now adds new scenario "asians-cloud/barfoo_scenario"
	pushUpdateToCollectionInHub()

	if err := UpdateHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to download index : %s", err)
	}

	getHubIdxOrFail(t)

	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Downloaded)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Installed)
	require.False(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].UpToDate)
	require.False(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Tainted)

	UpgradeConfig(cfg, COLLECTIONS, "asians-cloud/test_collection", false)
	assertCollectionDepsInstalled(t, "asians-cloud/test_collection")

	require.True(t, hubIdx[SCENARIOS]["asians-cloud/barfoo_scenario"].Downloaded)
	require.True(t, hubIdx[SCENARIOS]["asians-cloud/barfoo_scenario"].Installed)
}

// Install a collection, disable a scenario.
// Upgrade should install should not enable/download the disabled scenario.
func TestUpgradeConfigInDisabledScenarioShouldNotBeInstalled(t *testing.T) {
	cfg := envSetup(t)
	defer envTearDown(cfg)

	// fresh install of collection
	getHubIdxOrFail(t)

	require.False(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Downloaded)
	require.False(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Installed)
	require.False(t, hubIdx[SCENARIOS]["asians-cloud/foobar_scenario"].Installed)

	require.NoError(t, InstallItem(cfg, "asians-cloud/test_collection", COLLECTIONS, false, false))

	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Downloaded)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Installed)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].UpToDate)
	require.False(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Tainted)
	require.True(t, hubIdx[SCENARIOS]["asians-cloud/foobar_scenario"].Installed)
	assertCollectionDepsInstalled(t, "asians-cloud/test_collection")

	RemoveMany(cfg, SCENARIOS, "asians-cloud/foobar_scenario", false, false, false)
	getHubIdxOrFail(t)
	// scenario referenced by collection  was deleted hence, collection should be tainted
	require.False(t, hubIdx[SCENARIOS]["asians-cloud/foobar_scenario"].Installed)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Tainted)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Downloaded)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Installed)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].UpToDate)

	if err := UpdateHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to download index : %s", err)
	}

	UpgradeConfig(cfg, COLLECTIONS, "asians-cloud/test_collection", false)

	getHubIdxOrFail(t)
	require.False(t, hubIdx[SCENARIOS]["asians-cloud/foobar_scenario"].Installed)
}

func getHubIdxOrFail(t *testing.T) {
	if err := GetHubIdx(getTestCfg().Hub); err != nil {
		t.Fatalf("failed to load hub index")
	}
}

// Install a collection. Disable a referenced scenario. Publish new version of collection with new scenario
// Upgrade should not enable/download the disabled scenario.
// Upgrade should install and enable the newly added scenario.
func TestUpgradeConfigNewScenarioIsInstalledWhenReferencedScenarioIsDisabled(t *testing.T) {
	cfg := envSetup(t)
	defer envTearDown(cfg)

	// fresh install of collection
	getHubIdxOrFail(t)

	require.False(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Downloaded)
	require.False(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Installed)
	require.False(t, hubIdx[SCENARIOS]["asians-cloud/foobar_scenario"].Installed)

	require.NoError(t, InstallItem(cfg, "asians-cloud/test_collection", COLLECTIONS, false, false))

	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Downloaded)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Installed)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].UpToDate)
	require.False(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Tainted)
	require.True(t, hubIdx[SCENARIOS]["asians-cloud/foobar_scenario"].Installed)
	assertCollectionDepsInstalled(t, "asians-cloud/test_collection")

	RemoveMany(cfg, SCENARIOS, "asians-cloud/foobar_scenario", false, false, false)
	getHubIdxOrFail(t)
	// scenario referenced by collection  was deleted hence, collection should be tainted
	require.False(t, hubIdx[SCENARIOS]["asians-cloud/foobar_scenario"].Installed)
	require.True(t, hubIdx[SCENARIOS]["asians-cloud/foobar_scenario"].Downloaded) // this fails
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Tainted)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Downloaded)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].Installed)
	require.True(t, hubIdx[COLLECTIONS]["asians-cloud/test_collection"].UpToDate)

	// collection receives an update. It now adds new scenario "asians-cloud/barfoo_scenario"
	// we now attempt to upgrade the collection, however it shouldn't install the foobar_scenario
	// we just removed. Nor should it install the newly added scenario
	pushUpdateToCollectionInHub()

	if err := UpdateHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to download index : %s", err)
	}

	require.False(t, hubIdx[SCENARIOS]["asians-cloud/foobar_scenario"].Installed)
	getHubIdxOrFail(t)

	UpgradeConfig(cfg, COLLECTIONS, "asians-cloud/test_collection", false)
	getHubIdxOrFail(t)
	require.False(t, hubIdx[SCENARIOS]["asians-cloud/foobar_scenario"].Installed)
	require.True(t, hubIdx[SCENARIOS]["asians-cloud/barfoo_scenario"].Installed)
}

func assertCollectionDepsInstalled(t *testing.T, collection string) {
	t.Helper()

	c := hubIdx[COLLECTIONS][collection]
	require.NoError(t, CollecDepsCheck(&c))
}

func pushUpdateToCollectionInHub() {
	responseByPath["/master/.index.json"] = fileToStringX("./testdata/index2.json")
	responseByPath["/master/collections/asians-cloud/test_collection.yaml"] = fileToStringX("./testdata/collection_v2.yaml")
}
