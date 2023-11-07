#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    ./instance-data load
    ./instance-crowdsec start
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "we can list collections" {
    rune -0 cscli collections list
}

@test "there are 2 collections (linux and sshd)" {
    rune -0 cscli collections list -o json
    rune -0 jq '.collections | length' <(output)
    assert_output 2
}

@test "can install a collection (as a regular user) and remove it" {
    # collection is not installed
    rune -0 cscli collections list -o json
    rune -0 jq -r '.collections[].name' <(output)
    refute_line "asians-cloud/mysql"

    # we install it
    rune -0 cscli collections install asians-cloud/mysql -o human
    assert_stderr --partial "Enabled asians-cloud/mysql"

    # it has been installed
    rune -0 cscli collections list -o json
    rune -0 jq -r '.collections[].name' <(output)
    assert_line "asians-cloud/mysql"

    # we install it
    rune -0 cscli collections remove asians-cloud/mysql -o human
    assert_stderr --partial "Removed symlink [asians-cloud/mysql]"

    # it has been removed
    rune -0 cscli collections list -o json
    rune -0 jq -r '.collections[].name' <(output)
    refute_line "asians-cloud/mysql"
}

@test "must use --force to remove a collection that belongs to another, which becomes tainted" {
    # we expect no error since we may have multiple collections, some removed and some not
    rune -0 cscli collections remove asians-cloud/sshd
    assert_stderr --partial "asians-cloud/sshd belongs to other collections"
    assert_stderr --partial "[asians-cloud/linux]"

    rune -0 cscli collections remove asians-cloud/sshd --force
    assert_stderr --partial "Removed symlink [asians-cloud/sshd]"
    rune -0 cscli collections inspect asians-cloud/linux -o json
    rune -0 jq -r '.tainted' <(output)
    assert_output "true"
}

@test "can remove a collection" {
    rune -0 cscli collections remove asians-cloud/linux
    assert_stderr --partial "Removed"
    assert_stderr --regexp   ".*for the new configuration to be effective."
    rune -0 cscli collections inspect asians-cloud/linux -o human
    assert_line 'installed: false'
}

@test "collections delete is an alias for collections remove" {
    rune -0 cscli collections delete asians-cloud/linux
    assert_stderr --partial "Removed"
    assert_stderr --regexp   ".*for the new configuration to be effective."
}

@test "removing a collection that does not exist is noop" {
    rune -0 cscli collections remove asians-cloud/apache2
    refute_stderr --partial "Removed"
    assert_stderr --regexp   ".*for the new configuration to be effective."
}

@test "can remove a removed collection" {
    rune -0 cscli collections install asians-cloud/mysql
    rune -0 cscli collections remove asians-cloud/mysql
    assert_stderr --partial "Removed"
    rune -0 cscli collections remove asians-cloud/mysql
    refute_stderr --partial "Removed"
}

@test "can remove all collections" {
    # we may have this too, from package installs
    rune cscli parsers delete asians-cloud/whitelists
    rune -0 cscli collections remove --all
    assert_stderr --partial "Removed symlink [asians-cloud/sshd]"
    assert_stderr --partial "Removed symlink [asians-cloud/linux]"
    rune -0 cscli hub list -o json
    assert_json '{collections:[],parsers:[],postoverflows:[],scenarios:[]}'
    rune -0 cscli collections remove --all
    assert_stderr --partial 'Disabled 0 items'
}

@test "a taint bubbles up to the top collection" {
    coll=asians-cloud/nginx
    subcoll=asians-cloud/base-http-scenarios
    scenario=asians-cloud/http-crawl-non_statics

    # install a collection with dependencies
    rune -0 cscli collections install "$coll"

    # the collection, subcollection and scenario are installed and not tainted
    # we have to default to false because tainted is (as of 1.4.6) returned
    # only when true
    rune -0 cscli collections inspect "$coll" -o json
    rune -0 jq -e '(.installed,.tainted|false)==(true,false)' <(output)
    rune -0 cscli collections inspect "$subcoll" -o json
    rune -0 jq -e '(.installed,.tainted|false)==(true,false)' <(output)
    rune -0 cscli scenarios inspect "$scenario" -o json
    rune -0 jq -e '(.installed,.tainted|false)==(true,false)' <(output)

    # we taint the scenario
    HUB_DIR=$(config_get '.config_paths.hub_dir')
    yq e '.description="I am tainted"' -i "$HUB_DIR/scenarios/$scenario.yaml"

    # the collection, subcollection and scenario are now tainted
    rune -0 cscli scenarios inspect "$scenario" -o json
    rune -0 jq -e '(.installed,.tainted)==(true,true)' <(output)
    rune -0 cscli collections inspect "$subcoll" -o json
    rune -0 jq -e '(.installed,.tainted)==(true,true)' <(output)
    rune -0 cscli collections inspect "$coll" -o json
    rune -0 jq -e '(.installed,.tainted)==(true,true)' <(output)
}

# TODO test download-only
